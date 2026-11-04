use std::collections::HashSet;
use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

pub const MAGIC: u32 = 0xED0CDAED;
pub const VERSION: u32 = 2;
const NO_FREELIST: u64 = u64::MAX;
const META_FLAG: u16 = 0x04;
const BRANCH_FLAG: u16 = 0x01;
const LEAF_FLAG: u16 = 0x02;
const BUCKET_LEAF_FLAG: u32 = 0x01;
const PAGE_HEADER: usize = 16;
const META_BODY: usize = 64;
const LEAF_ELEM: usize = 16;
const BRANCH_ELEM: usize = 16;
const BUCKET_HEADER: usize = 16;
/// Pages 0 and 1 hold the meta pages.
const FIRST_DATA_PAGE: u64 = 2;
/// Deepest branch nesting accepted inside one bucket. bbolt splits nodes so
/// that every branch keeps at least two children, so depth grows as log2 of
/// the page count; real cache files are 1-3 levels deep. The bound keeps a
/// long chain of single-child pages from exhausting the stack.
const MAX_DEPTH: usize = 64;

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u16(&self, off: usize) -> io::Result<u16> {
        let b = self.bytes(off, 2).map_err(|_| err("u16 oob"))?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&self, off: usize) -> io::Result<u32> {
        let b = self.bytes(off, 4).map_err(|_| err("u32 oob"))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&self, off: usize) -> io::Result<u64> {
        let b = self.bytes(off, 8).map_err(|_| err("u64 oob"))?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn bytes(&self, off: usize, len: usize) -> io::Result<&'a [u8]> {
        off.checked_add(len)
            .and_then(|end| self.buf.get(off..end))
            .ok_or_else(|| err("bytes oob"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub page_size: u32,
    pub root: u64,
    pub sequence: u64,
    pub freelist: u64,
    pub pgid: u64,
    pub txid: u64,
}

fn parse_meta(page_prefix: &[u8]) -> Option<Meta> {
    let r = Reader { buf: page_prefix };
    if r.u32(PAGE_HEADER).ok()? != MAGIC || r.u32(PAGE_HEADER + 4).ok()? != VERSION {
        return None;
    }
    let stored = r.u64(PAGE_HEADER + 56).ok()?;
    if fnv1a64(page_prefix.get(PAGE_HEADER..PAGE_HEADER + 56)?) != stored {
        return None;
    }
    Some(Meta {
        page_size: r.u32(PAGE_HEADER + 8).ok()?,
        root: r.u64(PAGE_HEADER + 16).ok()?,
        sequence: r.u64(PAGE_HEADER + 24).ok()?,
        freelist: r.u64(PAGE_HEADER + 32).ok()?,
        pgid: r.u64(PAGE_HEADER + 40).ok()?,
        txid: r.u64(PAGE_HEADER + 48).ok()?,
    })
}

enum PageKind {
    Leaf,
    Branch,
}

/// One element, borrowing its key and value from the file image.
#[derive(Clone, Copy)]
struct Elem<'a> {
    flags: u32,
    key: &'a [u8],
    value: &'a [u8],
    child: u64,
}

fn page_kind(page: &[u8]) -> io::Result<PageKind> {
    match (Reader { buf: page }).u16(8)? {
        LEAF_FLAG => Ok(PageKind::Leaf),
        BRANCH_FLAG => Ok(PageKind::Branch),
        _ => Err(err("unexpected page type")),
    }
}

/// The element count, checked against the page so a bad count cannot
/// reserve memory the page does not have.
fn elem_count(page: &[u8], elem_size: usize) -> io::Result<usize> {
    let count = (Reader { buf: page }).u16(10)? as usize;
    if PAGE_HEADER + count * elem_size > page.len() {
        return Err(err("element table oob"));
    }
    Ok(count)
}

/// Keys and values of one page never overlap, so together they fit in it.
/// This bounds what one page can hand out.
fn add_payload(total: &mut usize, len: usize, page: &[u8]) -> io::Result<()> {
    *total = total.saturating_add(len);
    if *total > page.len() {
        return Err(err("page elements overlap"));
    }
    Ok(())
}

fn leaf_elems(page: &[u8]) -> io::Result<Vec<Elem<'_>>> {
    let r = Reader { buf: page };
    let count = elem_count(page, LEAF_ELEM)?;
    let mut out = Vec::with_capacity(count);
    let mut payload = 0usize;
    for i in 0..count {
        let e = PAGE_HEADER + i * LEAF_ELEM;
        let flags = r.u32(e)?;
        let pos = r.u32(e + 4)? as usize;
        let ksize = r.u32(e + 8)? as usize;
        let vsize = r.u32(e + 12)? as usize;
        let data = e.checked_add(pos).ok_or_else(|| err("bytes oob"))?;
        let key = r.bytes(data, ksize)?;
        let value = r.bytes(data + ksize, vsize)?;
        add_payload(&mut payload, ksize.saturating_add(vsize), page)?;
        out.push(Elem {
            flags,
            key,
            value,
            child: 0,
        });
    }
    Ok(out)
}

fn branch_elems(page: &[u8]) -> io::Result<Vec<Elem<'_>>> {
    let r = Reader { buf: page };
    let count = elem_count(page, BRANCH_ELEM)?;
    let mut out = Vec::with_capacity(count);
    let mut payload = 0usize;
    for i in 0..count {
        let e = PAGE_HEADER + i * BRANCH_ELEM;
        let pos = r.u32(e)? as usize;
        let ksize = r.u32(e + 4)? as usize;
        let pgid = r.u64(e + 8)?;
        let data = e.checked_add(pos).ok_or_else(|| err("bytes oob"))?;
        let key = r.bytes(data, ksize)?;
        add_payload(&mut payload, ksize, page)?;
        out.push(Elem {
            flags: 0,
            key,
            value: &[],
            child: pgid,
        });
    }
    Ok(out)
}

/// Pages already read by one lookup. In a valid file every page belongs to
/// exactly one node, so a page reached twice means a cycle or a shared
/// subtree, and each lookup reads each page at most once.
#[derive(Default)]
struct Visited {
    pages: HashSet<u64>,
}

/// A bucket's key/value pairs, in key order.
pub type BucketEntries = Vec<(String, Vec<u8>)>;
pub type RawBucketEntries = Vec<(Vec<u8>, Vec<u8>)>;

pub struct Db {
    data: Vec<u8>,
    page_size: usize,
    meta: Meta,
}

impl Db {
    pub fn open(path: &Path) -> io::Result<Db> {
        let data = fs::read(path)?;
        let mut found: Option<(Meta, usize)> = None;
        if data.len() >= PAGE_HEADER + META_BODY
            && let Some(m) = parse_meta(&data[0..PAGE_HEADER + META_BODY])
        {
            let ps = m.page_size as usize;
            if (256..=1 << 20).contains(&ps) && data.len() % ps == 0 {
                found = Some((m, ps));
            }
        }
        // bbolt alternates commits between the two meta pages; like `db.meta()`
        // in the reference, the valid one with the higher txid is current.
        let candidates = match found {
            Some((_, ps)) => vec![ps],
            None => vec![4096usize, 65536, 8192, 16384, 32768],
        };
        for cand in candidates {
            if data.len() < cand + PAGE_HEADER + META_BODY {
                continue;
            }
            if let Some(m) = parse_meta(&data[cand..cand + PAGE_HEADER + META_BODY])
                && m.page_size as usize == cand
                && data.len() % cand == 0
                && found.is_none_or(|(meta0, _)| m.txid > meta0.txid)
            {
                found = Some((m, cand));
                break;
            }
        }
        let (meta, page_size) = found.ok_or_else(|| err("no valid meta page"))?;
        if meta.root >= meta.pgid {
            return Err(err("root above high water mark"));
        }
        if meta.root < FIRST_DATA_PAGE {
            return Err(err("root points at a meta page"));
        }
        Ok(Db {
            data,
            page_size,
            meta,
        })
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// The root page of the bucket at `path`, or `None` if a segment is missing.
    fn bucket_at<'s>(
        &'s self,
        path: &[&str],
        visited: &mut Visited,
    ) -> io::Result<Option<&'s [u8]>> {
        let mut page = self.load_page(self.meta.root, visited)?;
        for segment in path {
            match self.find_bucket_in(page, segment.as_bytes(), visited, 0)? {
                Some(entry) => page = self.bucket_root_bytes(&entry, visited)?,
                None => return Ok(None),
            }
        }
        Ok(Some(page))
    }

    pub fn get(&self, path: &[&str], key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let mut visited = Visited::default();
        let page = self
            .bucket_at(path, &mut visited)?
            .ok_or_else(|| err("bucket not found"))?;
        // the bucket root may be a branch page when the bucket is wide
        match self.find_in_page(page, key, &mut visited, 0)? {
            Some(e) if e.flags & BUCKET_LEAF_FLAG == 0 => Ok(Some(e.value.to_vec())),
            _ => Ok(None),
        }
    }

    /// Depth-first lookup of a key in a node, descending branch pages.
    fn find_in_page<'s>(
        &'s self,
        page: &'s [u8],
        key: &[u8],
        visited: &mut Visited,
        depth: usize,
    ) -> io::Result<Option<Elem<'s>>> {
        match page_kind(page)? {
            PageKind::Leaf => Ok(leaf_elems(page)?.into_iter().find(|e| e.key == key)),
            PageKind::Branch => {
                let depth = deeper(depth)?;
                for e in branch_elems(page)? {
                    let child = self.load_page(e.child, visited)?;
                    if let Some(found) = self.find_in_page(child, key, visited, depth)? {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
        }
    }

    /// Every top-level bucket name, in key order.
    pub fn bucket_names(&self) -> io::Result<Vec<String>> {
        let mut visited = Visited::default();
        let root = self.load_page(self.meta.root, &mut visited)?;
        let mut elems = Vec::new();
        self.all_elems(root, &mut visited, 0, &mut elems)?;
        Ok(elems
            .into_iter()
            .filter(|elem| elem.flags & BUCKET_LEAF_FLAG != 0)
            .map(|elem| String::from_utf8_lossy(elem.key).to_string())
            .collect())
    }

    /// Every key/value of a bucket (depth first, in key order).
    pub fn bucket_page(&self, path: &[&str]) -> io::Result<Option<BucketEntries>> {
        Ok(self.bucket_page_raw(path)?.map(|entries| {
            entries
                .into_iter()
                .map(|(key, value)| (String::from_utf8_lossy(&key).to_string(), value))
                .collect()
        }))
    }

    /// Preserve binary keys such as sing-box's packed FakeIP addresses.
    pub fn bucket_page_raw(&self, path: &[&str]) -> io::Result<Option<RawBucketEntries>> {
        let mut visited = Visited::default();
        let page = self
            .bucket_at(path, &mut visited)?
            .ok_or_else(|| err("bucket not found"))?;
        let mut elems = Vec::new();
        self.all_elems(page, &mut visited, 0, &mut elems)?;
        Ok(Some(
            elems
                .into_iter()
                .filter(|elem| elem.flags & BUCKET_LEAF_FLAG == 0)
                .map(|elem| (elem.key.to_vec(), elem.value.to_vec()))
                .collect(),
        ))
    }

    /// All elements of a node, descending branch pages (keys stay sorted).
    fn all_elems<'s>(
        &'s self,
        page: &'s [u8],
        visited: &mut Visited,
        depth: usize,
        out: &mut Vec<Elem<'s>>,
    ) -> io::Result<()> {
        match page_kind(page)? {
            PageKind::Leaf => out.extend(leaf_elems(page)?),
            PageKind::Branch => {
                let depth = deeper(depth)?;
                for elem in branch_elems(page)? {
                    let child = self.load_page(elem.child, visited)?;
                    self.all_elems(child, visited, depth, out)?;
                }
            }
        }
        Ok(())
    }

    pub fn has_bucket(&self, path: &[&str]) -> io::Result<bool> {
        let mut visited = Visited::default();
        Ok(self.bucket_at(path, &mut visited)?.is_some())
    }

    /// A page plus its overflow continuation pages, so a leaf whose value
    /// spans several physical pages parses in one buffer. Every page id is
    /// checked against the meta high water mark and claimed in `visited`.
    fn load_page<'s>(&'s self, pgid: u64, visited: &mut Visited) -> io::Result<&'s [u8]> {
        if pgid < FIRST_DATA_PAGE {
            return Err(err("page id points at a meta page"));
        }
        if pgid >= self.meta.pgid {
            return Err(err("page id above high water mark"));
        }
        let page_size = self.page_size as u64;
        let data: &'s [u8] = &self.data;
        let span = |pages: u64| -> io::Result<&'s [u8]> {
            pgid.checked_mul(page_size)
                .zip(pages.checked_mul(page_size))
                .and_then(|(start, len)| {
                    Some((usize::try_from(start).ok()?, usize::try_from(len).ok()?))
                })
                .and_then(|(start, len)| data.get(start..start.checked_add(len)?))
                .ok_or_else(|| err("page oob"))
        };
        let first = span(1)?;
        if (Reader { buf: first }).u64(0)? != pgid {
            return Err(err("page id mismatch"));
        }
        let overflow = u64::from((Reader { buf: first }).u32(12)?);
        let last = pgid
            .checked_add(overflow)
            .filter(|last| *last < self.meta.pgid)
            .ok_or_else(|| err("overflow above high water mark"))?;
        let full = span(overflow + 1).map_err(|_| err("overflow page oob"))?;
        for id in pgid..=last {
            if !visited.pages.insert(id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("page {id} reached twice (page cycle or shared subtree)"),
                ));
            }
        }
        page_kind(full)?;
        Ok(full)
    }

    fn bucket_root_bytes<'s>(
        &'s self,
        entry: &Elem<'s>,
        visited: &mut Visited,
    ) -> io::Result<&'s [u8]> {
        if entry.value.len() < BUCKET_HEADER {
            return Err(err("short bucket header"));
        }
        let root = Reader { buf: entry.value }.u64(0)?;
        if root == NO_FREELIST {
            return Err(err("invalid bucket root"));
        }
        if root == 0 {
            let inline = &entry.value[BUCKET_HEADER..];
            page_kind(inline)?;
            Ok(inline)
        } else {
            self.load_page(root, visited)
        }
    }

    fn find_bucket_in<'s>(
        &'s self,
        page: &'s [u8],
        name: &[u8],
        visited: &mut Visited,
        depth: usize,
    ) -> io::Result<Option<Elem<'s>>> {
        match page_kind(page)? {
            PageKind::Leaf => Ok(leaf_elems(page)?
                .into_iter()
                .find(|e| e.key == name && e.flags & BUCKET_LEAF_FLAG != 0)),
            PageKind::Branch => {
                let depth = deeper(depth)?;
                for e in branch_elems(page)? {
                    let child = self.load_page(e.child, visited)?;
                    if let Some(found) = self.find_bucket_in(child, name, visited, depth)? {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
        }
    }
}

/// One branch level down, refusing trees deeper than `MAX_DEPTH`.
fn deeper(depth: usize) -> io::Result<usize> {
    if depth >= MAX_DEPTH {
        return Err(err("page tree too deep"));
    }
    Ok(depth + 1)
}

#[derive(Clone)]
pub enum EntrySpec {
    Kv(String, Vec<u8>),
    RawKv(Vec<u8>, Vec<u8>),
    Bucket {
        name: String,
        seq: u64,
        node: NodeSpec,
    },
}

#[derive(Clone)]
pub struct NodeSpec {
    pub entries: Vec<EntrySpec>,
}

impl NodeSpec {
    /// The same tree, borrowing every key and value.
    pub fn borrowed(&self) -> NodeRef<'_> {
        NodeRef {
            entries: self
                .entries
                .iter()
                .map(|entry| match entry {
                    EntrySpec::Kv(key, value) => EntryRef::Kv(key.as_bytes(), value),
                    EntrySpec::RawKv(key, value) => EntryRef::Kv(key, value),
                    EntrySpec::Bucket { name, seq, node } => EntryRef::Bucket {
                        name: name.as_bytes(),
                        seq: *seq,
                        node: node.borrowed(),
                    },
                })
                .collect(),
        }
    }
}

/// A tree that borrows its keys and values, so writing it copies each byte
/// once, straight into the file image.
pub enum EntryRef<'a> {
    Kv(&'a [u8], &'a [u8]),
    Bucket {
        name: &'a [u8],
        seq: u64,
        node: NodeRef<'a>,
    },
}

pub struct NodeRef<'a> {
    pub entries: Vec<EntryRef<'a>>,
}

impl<'a> EntryRef<'a> {
    fn key(&self) -> &'a [u8] {
        match self {
            EntryRef::Kv(key, _) => key,
            EntryRef::Bucket { name, .. } => name,
        }
    }
}

/// A leaf value: borrowed bytes, or the bucket header built for a child.
enum InodeValue<'a> {
    Data(&'a [u8]),
    Bucket([u8; BUCKET_HEADER]),
}

/// One leaf element of a B+tree node.
struct Inode<'a> {
    key: &'a [u8],
    flags: u32,
    value: InodeValue<'a>,
}

impl Inode<'_> {
    fn value(&self) -> &[u8] {
        match &self.value {
            InodeValue::Data(value) => value,
            InodeValue::Bucket(header) => header,
        }
    }
}

/// A bbolt writer: builds the tree bottom-up, spilling large nodes across
/// overflow pages and splitting wide nodes behind branch pages, so the file is
/// byte-compatible with go.etcd.io/bbolt readers.
struct Writer<W> {
    page_size: usize,
    next_pgid: u64,
    file: W,
}

impl<W: Write + Seek> Writer<W> {
    fn new(mut file: W, page_size: usize) -> io::Result<Self> {
        file.seek(SeekFrom::Start(0))?;
        let mut writer = Self {
            page_size,
            next_pgid: 2,
            file,
        };
        writer.zeros(2 * page_size)?;
        Ok(writer)
    }

    fn alloc(&mut self, npages: usize) -> u64 {
        let pgid = self.next_pgid;
        self.next_pgid += npages as u64;
        pgid
    }

    fn zeros(&mut self, mut bytes: usize) -> io::Result<()> {
        let zeroes = [0u8; 4096];
        while bytes > 0 {
            let chunk = bytes.min(zeroes.len());
            self.file.write_all(&zeroes[..chunk])?;
            bytes -= chunk;
        }
        Ok(())
    }

    fn page_header(
        &mut self,
        pgid: u64,
        flags: u16,
        count: usize,
        overflow: usize,
    ) -> io::Result<()> {
        // Data pages are allocated and emitted consecutively. Only metadata
        // needs a seek, so buffered disk writes stay sequential here.
        self.file.write_all(&pgid.to_le_bytes())?;
        self.file.write_all(&flags.to_le_bytes())?;
        self.file.write_all(&(count as u16).to_le_bytes())?;
        self.file.write_all(&(overflow as u32).to_le_bytes())
    }

    /// Materialize a node and everything under it; returns its root pgid.
    /// Entries are sorted first, so child buckets get pages in key order.
    fn materialize(&mut self, mut node: NodeRef<'_>) -> io::Result<u64> {
        node.entries.sort_by(|a, b| a.key().cmp(b.key()));
        let mut inodes = Vec::with_capacity(node.entries.len());
        for entry in node.entries {
            match entry {
                EntryRef::Kv(key, value) => inodes.push(Inode {
                    key,
                    flags: 0,
                    value: InodeValue::Data(value),
                }),
                EntryRef::Bucket { name, seq, node } => {
                    let child_pgid = self.materialize(node)?;
                    let mut header = [0u8; BUCKET_HEADER];
                    header[0..8].copy_from_slice(&child_pgid.to_le_bytes());
                    header[8..16].copy_from_slice(&seq.to_le_bytes());
                    inodes.push(Inode {
                        key: name,
                        flags: BUCKET_LEAF_FLAG,
                        value: InodeValue::Bucket(header),
                    });
                }
            }
        }
        self.spill(&inodes)
    }

    fn spill(&mut self, inodes: &[Inode<'_>]) -> io::Result<u64> {
        if inodes.is_empty() {
            return self.write_leaf(&[]);
        }
        let leaves = self.partition(inodes);
        if leaves.len() == 1 {
            // one logical node: overflow pages if a value is large
            return self.write_leaf(inodes);
        }
        let mut refs = Vec::with_capacity(leaves.len());
        for range in leaves {
            let leaf = &inodes[range];
            let pgid = self.write_leaf(leaf)?;
            refs.push((leaf[0].key, pgid));
        }
        self.build_branch(refs)
    }

    /// Greedy split into leaves that fit a page; a single oversized inode gets
    /// its own leaf and spills over.
    fn partition(&self, inodes: &[Inode<'_>]) -> Vec<std::ops::Range<usize>> {
        let mut leaves = Vec::new();
        let mut start = 0;
        let mut size = PAGE_HEADER;
        for (i, inode) in inodes.iter().enumerate() {
            let elem = LEAF_ELEM + inode.key.len() + inode.value().len();
            if i > start && size + elem > self.page_size {
                leaves.push(start..i);
                start = i;
                size = PAGE_HEADER;
            }
            size += elem;
        }
        if start < inodes.len() {
            leaves.push(start..inodes.len());
        }
        leaves
    }

    fn write_leaf(&mut self, inodes: &[Inode<'_>]) -> io::Result<u64> {
        let total = PAGE_HEADER
            + LEAF_ELEM * inodes.len()
            + inodes
                .iter()
                .map(|inode| inode.key.len() + inode.value().len())
                .sum::<usize>();
        let npages = total.div_ceil(self.page_size).max(1);
        let pgid = self.alloc(npages);
        self.page_header(pgid, LEAF_FLAG, inodes.len(), npages - 1)?;
        let mut data_off = PAGE_HEADER + LEAF_ELEM * inodes.len();
        for (i, inode) in inodes.iter().enumerate() {
            let value = inode.value();
            let elem = PAGE_HEADER + i * LEAF_ELEM;
            let pos = (data_off - elem) as u32;
            self.file.write_all(&inode.flags.to_le_bytes())?;
            self.file.write_all(&pos.to_le_bytes())?;
            self.file
                .write_all(&(inode.key.len() as u32).to_le_bytes())?;
            self.file.write_all(&(value.len() as u32).to_le_bytes())?;
            data_off += inode.key.len() + value.len();
        }
        for inode in inodes {
            self.file.write_all(inode.key)?;
            self.file.write_all(inode.value())?;
        }
        self.zeros(npages * self.page_size - total)?;
        Ok(pgid)
    }

    /// Branch pages, recursing into branch-of-branches when the index is wide.
    fn build_branch(&mut self, refs: Vec<(&[u8], u64)>) -> io::Result<u64> {
        if branch_size(&refs) <= self.page_size {
            return self.write_branch_page(&refs);
        }
        let mut groups: Vec<Vec<(&[u8], u64)>> = Vec::new();
        let mut current: Vec<(&[u8], u64)> = Vec::new();
        let mut size = PAGE_HEADER;
        for item in refs {
            let elem = BRANCH_ELEM + item.0.len();
            if !current.is_empty() && size + elem > self.page_size {
                groups.push(std::mem::take(&mut current));
                size = PAGE_HEADER;
            }
            current.push(item);
            size += elem;
        }
        if !current.is_empty() {
            groups.push(current);
        }
        let mut child_refs = Vec::with_capacity(groups.len());
        for group in groups {
            let first = group[0].0;
            let pgid = self.write_branch_page(&group)?;
            child_refs.push((first, pgid));
        }
        self.build_branch(child_refs)
    }

    fn write_branch_page(&mut self, refs: &[(&[u8], u64)]) -> io::Result<u64> {
        let pgid = self.alloc(1);
        self.page_header(pgid, BRANCH_FLAG, refs.len(), 0)?;
        let mut data_off = PAGE_HEADER + BRANCH_ELEM * refs.len();
        for (i, (key, child)) in refs.iter().enumerate() {
            let elem = PAGE_HEADER + i * BRANCH_ELEM;
            let pos = (data_off - elem) as u32;
            self.file.write_all(&pos.to_le_bytes())?;
            self.file.write_all(&(key.len() as u32).to_le_bytes())?;
            self.file.write_all(&child.to_le_bytes())?;
            data_off += key.len();
        }
        for (key, _) in refs {
            self.file.write_all(key)?;
        }
        self.zeros(self.page_size - data_off)?;
        Ok(pgid)
    }

    fn write_meta(&mut self, root_pgid: u64) -> io::Result<()> {
        let high_water = self.next_pgid;
        for (id, txid) in [(0u64, 0u64), (1u64, 1u64)] {
            let mut page = vec![0u8; self.page_size];
            page[0..8].copy_from_slice(&id.to_le_bytes());
            page[8..10].copy_from_slice(&META_FLAG.to_le_bytes());
            let mut meta = vec![0u8; META_BODY];
            meta[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            meta[4..8].copy_from_slice(&VERSION.to_le_bytes());
            meta[8..12].copy_from_slice(&(self.page_size as u32).to_le_bytes());
            meta[16..24].copy_from_slice(&root_pgid.to_le_bytes());
            meta[24..32].copy_from_slice(&0u64.to_le_bytes());
            meta[32..40].copy_from_slice(&NO_FREELIST.to_le_bytes());
            meta[40..48].copy_from_slice(&high_water.to_le_bytes());
            meta[48..56].copy_from_slice(&txid.to_le_bytes());
            let sum = fnv1a64(&meta[0..56]);
            meta[56..64].copy_from_slice(&sum.to_le_bytes());
            page[PAGE_HEADER..PAGE_HEADER + META_BODY].copy_from_slice(&meta);
            self.file
                .seek(SeekFrom::Start(id * self.page_size as u64))?;
            self.file.write_all(&page)?;
        }
        Ok(())
    }
}

fn branch_size(refs: &[(&[u8], u64)]) -> usize {
    PAGE_HEADER + BRANCH_ELEM * refs.len() + refs.iter().map(|r| r.0.len()).sum::<usize>()
}

pub fn write(path: &Path, root: &NodeSpec) -> io::Result<()> {
    write_ref(path, root.borrowed())
}

/// Write a borrowed tree; the output is the same as `write` for the same
/// content.
pub fn write_ref(path: &Path, root: NodeRef<'_>) -> io::Result<()> {
    let file = fs::File::create(path)?;
    write_to(io::BufWriter::with_capacity(32 * 1024, file), root)
}

/// The file image `write_ref` would write, for callers that do their own
/// file handling (for example a synced replace).
pub fn encode_ref(root: NodeRef<'_>) -> io::Result<Vec<u8>> {
    let mut output = io::Cursor::new(Vec::new());
    write_to(&mut output, root)?;
    Ok(output.into_inner())
}

/// Serialize directly into an initially empty/truncated seekable destination.
/// The destination is flushed on success; durability and atomic replacement
/// remain the caller's responsibility. Large values are written by reference.
pub fn write_to<W: Write + Seek>(output: W, root: NodeRef<'_>) -> io::Result<()> {
    let mut writer = Writer::new(output, 4096)?;
    let root_pgid = writer.materialize(root)?;
    writer.write_meta(root_pgid)?;
    writer.file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_propagates_partial_write_metadata_seek_and_flush_errors() {
        struct Faulty {
            inner: io::Cursor<Vec<u8>>,
            bytes_left: usize,
            seeks: usize,
            fail_seek: bool,
            fail_flush: bool,
        }
        impl Write for Faulty {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.bytes_left == 0 {
                    return Err(io::Error::other("injected partial write"));
                }
                let count = bytes.len().min(self.bytes_left).min(113);
                self.bytes_left -= count;
                self.inner.write(&bytes[..count])
            }
            fn flush(&mut self) -> io::Result<()> {
                if self.fail_flush {
                    Err(io::Error::other("injected flush"))
                } else {
                    Ok(())
                }
            }
        }
        impl Seek for Faulty {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                self.seeks += 1;
                if self.fail_seek && self.seeks == 2 {
                    return Err(io::Error::other("injected metadata seek"));
                }
                self.inner.seek(position)
            }
        }
        let value = vec![1; 10000];
        for (bytes_left, fail_seek, fail_flush, expected) in [
            (9000, false, false, "partial write"),
            (usize::MAX, true, false, "metadata seek"),
            (usize::MAX, false, true, "flush"),
        ] {
            let output = Faulty {
                inner: io::Cursor::new(Vec::new()),
                bytes_left,
                seeks: 0,
                fail_seek,
                fail_flush,
            };
            let error = write_to(
                output,
                NodeRef {
                    entries: vec![EntryRef::Kv(b"k", &value)],
                },
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn borrowed_tree_writes_the_same_bytes() {
        let owned: Vec<(Vec<u8>, Vec<u8>)> = (0..300u32)
            .rev()
            .map(|i| (format!("key-{i:04}").into_bytes(), vec![i as u8; 40]))
            .collect();
        let spec = NodeSpec {
            entries: vec![EntrySpec::Bucket {
                name: "b".into(),
                seq: 3,
                node: NodeSpec {
                    entries: owned
                        .iter()
                        .map(|(k, v)| EntrySpec::RawKv(k.clone(), v.clone()))
                        .collect(),
                },
            }],
        };
        let borrowed = NodeRef {
            entries: vec![EntryRef::Bucket {
                name: b"b",
                seq: 3,
                node: NodeRef {
                    entries: owned.iter().map(|(k, v)| EntryRef::Kv(k, v)).collect(),
                },
            }],
        };
        let dir = std::env::temp_dir();
        let a = dir.join(format!("bbolt-owned-{}.db", std::process::id()));
        let b = dir.join(format!("bbolt-borrowed-{}.db", std::process::id()));
        write(&a, &spec).unwrap();
        write_ref(&b, borrowed).unwrap();
        assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
        let db = Db::open(&b).unwrap();
        assert_eq!(db.get(&["b"], b"key-0007").unwrap(), Some(vec![7; 40]));
        fs::remove_file(a).unwrap();
        fs::remove_file(b).unwrap();
    }
}
