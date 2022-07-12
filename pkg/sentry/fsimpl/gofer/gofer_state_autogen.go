// automatically generated by stateify.

package gofer

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (l *dentryList) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentryList"
}

func (l *dentryList) StateFields() []string {
	return []string{
		"head",
		"tail",
	}
}

func (l *dentryList) beforeSave() {}

// +checklocksignore
func (l *dentryList) StateSave(stateSinkObject state.Sink) {
	l.beforeSave()
	stateSinkObject.Save(0, &l.head)
	stateSinkObject.Save(1, &l.tail)
}

func (l *dentryList) afterLoad() {}

// +checklocksignore
func (l *dentryList) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &l.head)
	stateSourceObject.Load(1, &l.tail)
}

func (e *dentryEntry) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentryEntry"
}

func (e *dentryEntry) StateFields() []string {
	return []string{
		"next",
		"prev",
	}
}

func (e *dentryEntry) beforeSave() {}

// +checklocksignore
func (e *dentryEntry) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.next)
	stateSinkObject.Save(1, &e.prev)
}

func (e *dentryEntry) afterLoad() {}

// +checklocksignore
func (e *dentryEntry) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.next)
	stateSourceObject.Load(1, &e.prev)
}

func (fd *directoryFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.directoryFD"
}

func (fd *directoryFD) StateFields() []string {
	return []string{
		"fileDescription",
		"DirectoryFileDescriptionDefaultImpl",
		"off",
		"dirents",
	}
}

func (fd *directoryFD) beforeSave() {}

// +checklocksignore
func (fd *directoryFD) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.fileDescription)
	stateSinkObject.Save(1, &fd.DirectoryFileDescriptionDefaultImpl)
	stateSinkObject.Save(2, &fd.off)
	stateSinkObject.Save(3, &fd.dirents)
}

func (fd *directoryFD) afterLoad() {}

// +checklocksignore
func (fd *directoryFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.fileDescription)
	stateSourceObject.Load(1, &fd.DirectoryFileDescriptionDefaultImpl)
	stateSourceObject.Load(2, &fd.off)
	stateSourceObject.Load(3, &fd.dirents)
}

func (d *dentryCache) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentryCache"
}

func (d *dentryCache) StateFields() []string {
	return []string{
		"dentries",
		"dentriesLen",
		"maxCachedDentries",
	}
}

func (d *dentryCache) beforeSave() {}

// +checklocksignore
func (d *dentryCache) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.dentries)
	stateSinkObject.Save(1, &d.dentriesLen)
	stateSinkObject.Save(2, &d.maxCachedDentries)
}

func (d *dentryCache) afterLoad() {}

// +checklocksignore
func (d *dentryCache) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.dentries)
	stateSourceObject.Load(1, &d.dentriesLen)
	stateSourceObject.Load(2, &d.maxCachedDentries)
}

func (fstype *FilesystemType) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.FilesystemType"
}

func (fstype *FilesystemType) StateFields() []string {
	return []string{}
}

func (fstype *FilesystemType) beforeSave() {}

// +checklocksignore
func (fstype *FilesystemType) StateSave(stateSinkObject state.Sink) {
	fstype.beforeSave()
}

func (fstype *FilesystemType) afterLoad() {}

// +checklocksignore
func (fstype *FilesystemType) StateLoad(stateSourceObject state.Source) {
}

func (fs *filesystem) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.filesystem"
}

func (fs *filesystem) StateFields() []string {
	return []string{
		"vfsfs",
		"mfp",
		"opts",
		"iopts",
		"clock",
		"devMinor",
		"root",
		"dentryCache",
		"syncableDentries",
		"specialFileFDs",
		"lastIno",
		"savedDentryRW",
		"released",
	}
}

func (fs *filesystem) beforeSave() {}

// +checklocksignore
func (fs *filesystem) StateSave(stateSinkObject state.Sink) {
	fs.beforeSave()
	stateSinkObject.Save(0, &fs.vfsfs)
	stateSinkObject.Save(1, &fs.mfp)
	stateSinkObject.Save(2, &fs.opts)
	stateSinkObject.Save(3, &fs.iopts)
	stateSinkObject.Save(4, &fs.clock)
	stateSinkObject.Save(5, &fs.devMinor)
	stateSinkObject.Save(6, &fs.root)
	stateSinkObject.Save(7, &fs.dentryCache)
	stateSinkObject.Save(8, &fs.syncableDentries)
	stateSinkObject.Save(9, &fs.specialFileFDs)
	stateSinkObject.Save(10, &fs.lastIno)
	stateSinkObject.Save(11, &fs.savedDentryRW)
	stateSinkObject.Save(12, &fs.released)
}

func (fs *filesystem) afterLoad() {}

// +checklocksignore
func (fs *filesystem) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fs.vfsfs)
	stateSourceObject.Load(1, &fs.mfp)
	stateSourceObject.Load(2, &fs.opts)
	stateSourceObject.Load(3, &fs.iopts)
	stateSourceObject.Load(4, &fs.clock)
	stateSourceObject.Load(5, &fs.devMinor)
	stateSourceObject.Load(6, &fs.root)
	stateSourceObject.Load(7, &fs.dentryCache)
	stateSourceObject.Load(8, &fs.syncableDentries)
	stateSourceObject.Load(9, &fs.specialFileFDs)
	stateSourceObject.Load(10, &fs.lastIno)
	stateSourceObject.Load(11, &fs.savedDentryRW)
	stateSourceObject.Load(12, &fs.released)
}

func (f *filesystemOptions) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.filesystemOptions"
}

func (f *filesystemOptions) StateFields() []string {
	return []string{
		"fd",
		"aname",
		"interop",
		"dfltuid",
		"dfltgid",
		"msize",
		"version",
		"forcePageCache",
		"limitHostFDTranslation",
		"overlayfsStaleRead",
		"regularFilesUseSpecialFileFD",
		"lisaEnabled",
	}
}

func (f *filesystemOptions) beforeSave() {}

// +checklocksignore
func (f *filesystemOptions) StateSave(stateSinkObject state.Sink) {
	f.beforeSave()
	stateSinkObject.Save(0, &f.fd)
	stateSinkObject.Save(1, &f.aname)
	stateSinkObject.Save(2, &f.interop)
	stateSinkObject.Save(3, &f.dfltuid)
	stateSinkObject.Save(4, &f.dfltgid)
	stateSinkObject.Save(5, &f.msize)
	stateSinkObject.Save(6, &f.version)
	stateSinkObject.Save(7, &f.forcePageCache)
	stateSinkObject.Save(8, &f.limitHostFDTranslation)
	stateSinkObject.Save(9, &f.overlayfsStaleRead)
	stateSinkObject.Save(10, &f.regularFilesUseSpecialFileFD)
	stateSinkObject.Save(11, &f.lisaEnabled)
}

func (f *filesystemOptions) afterLoad() {}

// +checklocksignore
func (f *filesystemOptions) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &f.fd)
	stateSourceObject.Load(1, &f.aname)
	stateSourceObject.Load(2, &f.interop)
	stateSourceObject.Load(3, &f.dfltuid)
	stateSourceObject.Load(4, &f.dfltgid)
	stateSourceObject.Load(5, &f.msize)
	stateSourceObject.Load(6, &f.version)
	stateSourceObject.Load(7, &f.forcePageCache)
	stateSourceObject.Load(8, &f.limitHostFDTranslation)
	stateSourceObject.Load(9, &f.overlayfsStaleRead)
	stateSourceObject.Load(10, &f.regularFilesUseSpecialFileFD)
	stateSourceObject.Load(11, &f.lisaEnabled)
}

func (i *InteropMode) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.InteropMode"
}

func (i *InteropMode) StateFields() []string {
	return nil
}

func (i *InternalFilesystemOptions) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.InternalFilesystemOptions"
}

func (i *InternalFilesystemOptions) StateFields() []string {
	return []string{
		"UniqueID",
		"LeakConnection",
		"OpenSocketsByConnecting",
	}
}

func (i *InternalFilesystemOptions) beforeSave() {}

// +checklocksignore
func (i *InternalFilesystemOptions) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
	stateSinkObject.Save(0, &i.UniqueID)
	stateSinkObject.Save(1, &i.LeakConnection)
	stateSinkObject.Save(2, &i.OpenSocketsByConnecting)
}

func (i *InternalFilesystemOptions) afterLoad() {}

// +checklocksignore
func (i *InternalFilesystemOptions) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &i.UniqueID)
	stateSourceObject.Load(1, &i.LeakConnection)
	stateSourceObject.Load(2, &i.OpenSocketsByConnecting)
}

func (i *inoKey) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.inoKey"
}

func (i *inoKey) StateFields() []string {
	return []string{
		"ino",
		"devMinor",
		"devMajor",
	}
}

func (i *inoKey) beforeSave() {}

// +checklocksignore
func (i *inoKey) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
	stateSinkObject.Save(0, &i.ino)
	stateSinkObject.Save(1, &i.devMinor)
	stateSinkObject.Save(2, &i.devMajor)
}

func (i *inoKey) afterLoad() {}

// +checklocksignore
func (i *inoKey) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &i.ino)
	stateSourceObject.Load(1, &i.devMinor)
	stateSourceObject.Load(2, &i.devMajor)
}

func (d *dentry) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentry"
}

func (d *dentry) StateFields() []string {
	return []string{
		"vfsd",
		"refs",
		"fs",
		"parent",
		"name",
		"qidPath",
		"inoKey",
		"deleted",
		"cached",
		"dentryEntry",
		"children",
		"syntheticChildren",
		"dirents",
		"childrenSet",
		"ino",
		"mode",
		"uid",
		"gid",
		"blockSize",
		"atime",
		"mtime",
		"ctime",
		"btime",
		"size",
		"atimeDirty",
		"mtimeDirty",
		"nlink",
		"mappings",
		"cache",
		"dirty",
		"pf",
		"haveTarget",
		"target",
		"endpoint",
		"pipe",
		"locks",
		"watches",
	}
}

// +checklocksignore
func (d *dentry) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.vfsd)
	stateSinkObject.Save(1, &d.refs)
	stateSinkObject.Save(2, &d.fs)
	stateSinkObject.Save(3, &d.parent)
	stateSinkObject.Save(4, &d.name)
	stateSinkObject.Save(5, &d.qidPath)
	stateSinkObject.Save(6, &d.inoKey)
	stateSinkObject.Save(7, &d.deleted)
	stateSinkObject.Save(8, &d.cached)
	stateSinkObject.Save(9, &d.dentryEntry)
	stateSinkObject.Save(10, &d.children)
	stateSinkObject.Save(11, &d.syntheticChildren)
	stateSinkObject.Save(12, &d.dirents)
	stateSinkObject.Save(13, &d.childrenSet)
	stateSinkObject.Save(14, &d.ino)
	stateSinkObject.Save(15, &d.mode)
	stateSinkObject.Save(16, &d.uid)
	stateSinkObject.Save(17, &d.gid)
	stateSinkObject.Save(18, &d.blockSize)
	stateSinkObject.Save(19, &d.atime)
	stateSinkObject.Save(20, &d.mtime)
	stateSinkObject.Save(21, &d.ctime)
	stateSinkObject.Save(22, &d.btime)
	stateSinkObject.Save(23, &d.size)
	stateSinkObject.Save(24, &d.atimeDirty)
	stateSinkObject.Save(25, &d.mtimeDirty)
	stateSinkObject.Save(26, &d.nlink)
	stateSinkObject.Save(27, &d.mappings)
	stateSinkObject.Save(28, &d.cache)
	stateSinkObject.Save(29, &d.dirty)
	stateSinkObject.Save(30, &d.pf)
	stateSinkObject.Save(31, &d.haveTarget)
	stateSinkObject.Save(32, &d.target)
	stateSinkObject.Save(33, &d.endpoint)
	stateSinkObject.Save(34, &d.pipe)
	stateSinkObject.Save(35, &d.locks)
	stateSinkObject.Save(36, &d.watches)
}

// +checklocksignore
func (d *dentry) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.vfsd)
	stateSourceObject.Load(1, &d.refs)
	stateSourceObject.Load(2, &d.fs)
	stateSourceObject.Load(3, &d.parent)
	stateSourceObject.Load(4, &d.name)
	stateSourceObject.Load(5, &d.qidPath)
	stateSourceObject.Load(6, &d.inoKey)
	stateSourceObject.Load(7, &d.deleted)
	stateSourceObject.Load(8, &d.cached)
	stateSourceObject.Load(9, &d.dentryEntry)
	stateSourceObject.Load(10, &d.children)
	stateSourceObject.Load(11, &d.syntheticChildren)
	stateSourceObject.Load(12, &d.dirents)
	stateSourceObject.Load(13, &d.childrenSet)
	stateSourceObject.Load(14, &d.ino)
	stateSourceObject.Load(15, &d.mode)
	stateSourceObject.Load(16, &d.uid)
	stateSourceObject.Load(17, &d.gid)
	stateSourceObject.Load(18, &d.blockSize)
	stateSourceObject.Load(19, &d.atime)
	stateSourceObject.Load(20, &d.mtime)
	stateSourceObject.Load(21, &d.ctime)
	stateSourceObject.Load(22, &d.btime)
	stateSourceObject.Load(23, &d.size)
	stateSourceObject.Load(24, &d.atimeDirty)
	stateSourceObject.Load(25, &d.mtimeDirty)
	stateSourceObject.Load(26, &d.nlink)
	stateSourceObject.Load(27, &d.mappings)
	stateSourceObject.Load(28, &d.cache)
	stateSourceObject.Load(29, &d.dirty)
	stateSourceObject.Load(30, &d.pf)
	stateSourceObject.Load(31, &d.haveTarget)
	stateSourceObject.Load(32, &d.target)
	stateSourceObject.Load(33, &d.endpoint)
	stateSourceObject.Load(34, &d.pipe)
	stateSourceObject.Load(35, &d.locks)
	stateSourceObject.Load(36, &d.watches)
	stateSourceObject.AfterLoad(d.afterLoad)
}

func (fd *fileDescription) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.fileDescription"
}

func (fd *fileDescription) StateFields() []string {
	return []string{
		"vfsfd",
		"FileDescriptionDefaultImpl",
		"LockFD",
	}
}

func (fd *fileDescription) beforeSave() {}

// +checklocksignore
func (fd *fileDescription) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.vfsfd)
	stateSinkObject.Save(1, &fd.FileDescriptionDefaultImpl)
	stateSinkObject.Save(2, &fd.LockFD)
}

func (fd *fileDescription) afterLoad() {}

// +checklocksignore
func (fd *fileDescription) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.vfsfd)
	stateSourceObject.Load(1, &fd.FileDescriptionDefaultImpl)
	stateSourceObject.Load(2, &fd.LockFD)
}

func (fd *regularFileFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.regularFileFD"
}

func (fd *regularFileFD) StateFields() []string {
	return []string{
		"fileDescription",
		"off",
	}
}

func (fd *regularFileFD) beforeSave() {}

// +checklocksignore
func (fd *regularFileFD) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.fileDescription)
	stateSinkObject.Save(1, &fd.off)
}

func (fd *regularFileFD) afterLoad() {}

// +checklocksignore
func (fd *regularFileFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.fileDescription)
	stateSourceObject.Load(1, &fd.off)
}

func (d *dentryPlatformFile) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentryPlatformFile"
}

func (d *dentryPlatformFile) StateFields() []string {
	return []string{
		"dentry",
		"fdRefs",
		"hostFileMapper",
	}
}

func (d *dentryPlatformFile) beforeSave() {}

// +checklocksignore
func (d *dentryPlatformFile) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.dentry)
	stateSinkObject.Save(1, &d.fdRefs)
	stateSinkObject.Save(2, &d.hostFileMapper)
}

// +checklocksignore
func (d *dentryPlatformFile) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.dentry)
	stateSourceObject.Load(1, &d.fdRefs)
	stateSourceObject.Load(2, &d.hostFileMapper)
	stateSourceObject.AfterLoad(d.afterLoad)
}

func (s *savedDentryRW) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.savedDentryRW"
}

func (s *savedDentryRW) StateFields() []string {
	return []string{
		"read",
		"write",
	}
}

func (s *savedDentryRW) beforeSave() {}

// +checklocksignore
func (s *savedDentryRW) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.read)
	stateSinkObject.Save(1, &s.write)
}

func (s *savedDentryRW) afterLoad() {}

// +checklocksignore
func (s *savedDentryRW) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.read)
	stateSourceObject.Load(1, &s.write)
}

func (e *endpoint) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.endpoint"
}

func (e *endpoint) StateFields() []string {
	return []string{
		"dentry",
		"path",
	}
}

func (e *endpoint) beforeSave() {}

// +checklocksignore
func (e *endpoint) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.dentry)
	stateSinkObject.Save(1, &e.path)
}

func (e *endpoint) afterLoad() {}

// +checklocksignore
func (e *endpoint) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.dentry)
	stateSourceObject.Load(1, &e.path)
}

func (fd *specialFileFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.specialFileFD"
}

func (fd *specialFileFD) StateFields() []string {
	return []string{
		"fileDescription",
		"isRegularFile",
		"seekable",
		"queue",
		"off",
		"haveBuf",
		"buf",
		"hostFileMapper",
		"fileRefs",
	}
}

func (fd *specialFileFD) beforeSave() {}

// +checklocksignore
func (fd *specialFileFD) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.fileDescription)
	stateSinkObject.Save(1, &fd.isRegularFile)
	stateSinkObject.Save(2, &fd.seekable)
	stateSinkObject.Save(3, &fd.queue)
	stateSinkObject.Save(4, &fd.off)
	stateSinkObject.Save(5, &fd.haveBuf)
	stateSinkObject.Save(6, &fd.buf)
	stateSinkObject.Save(7, &fd.hostFileMapper)
	stateSinkObject.Save(8, &fd.fileRefs)
}

// +checklocksignore
func (fd *specialFileFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.fileDescription)
	stateSourceObject.Load(1, &fd.isRegularFile)
	stateSourceObject.Load(2, &fd.seekable)
	stateSourceObject.Load(3, &fd.queue)
	stateSourceObject.Load(4, &fd.off)
	stateSourceObject.Load(5, &fd.haveBuf)
	stateSourceObject.Load(6, &fd.buf)
	stateSourceObject.Load(7, &fd.hostFileMapper)
	stateSourceObject.Load(8, &fd.fileRefs)
	stateSourceObject.AfterLoad(fd.afterLoad)
}

func init() {
	state.Register((*dentryList)(nil))
	state.Register((*dentryEntry)(nil))
	state.Register((*directoryFD)(nil))
	state.Register((*dentryCache)(nil))
	state.Register((*FilesystemType)(nil))
	state.Register((*filesystem)(nil))
	state.Register((*filesystemOptions)(nil))
	state.Register((*InteropMode)(nil))
	state.Register((*InternalFilesystemOptions)(nil))
	state.Register((*inoKey)(nil))
	state.Register((*dentry)(nil))
	state.Register((*fileDescription)(nil))
	state.Register((*regularFileFD)(nil))
	state.Register((*dentryPlatformFile)(nil))
	state.Register((*savedDentryRW)(nil))
	state.Register((*endpoint)(nil))
	state.Register((*specialFileFD)(nil))
}