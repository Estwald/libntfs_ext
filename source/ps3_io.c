
/* 
    (c) 2013 Estwald <www.elotrolado.net>

    "ps3_io.c" is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    "ps3_io.c" is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with HMANAGER4.  If not, see <http://www.gnu.org/licenses/>.

*/

#if defined(PS3_GEKKO)

#include "ntfs.h"
#include "iosupport.h"
#include "storage.h"
#include <malloc.h>

#include <sys/file.h>

#define FS_S_IFMT 0170000
#define UMASK(mode)		((mode)&~g_umask)
extern mode_t g_umask;

struct passwd * getpwnam(const char *name) { return 0; }
struct passwd * getpwuid(uid_t uid) { return 0; }
struct group	*getgrnam (const char * x)  { return 0; }
struct group	*getgrgid (gid_t x){ return 0; }
uid_t getuid(void) { return 0; }
gid_t getgid () { return -1; }

const devoptab_t *devoptab_list[33]={
    NULL, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};


static int dev_fd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static int dev_sectsize[8] = {512, 512, 512, 512, 512, 512, 512, 512};

bool PS3_NTFS_Startup(u64 id, int fd)
{
    int rr;
    
	static device_info_t disc_info;

    if(fd < 0 || fd > 7) return false;
   
    disc_info.unknown03 = 0x12345678; // hack for Iris Manager Disc Less
    disc_info.sector_size = 0;
    rr=sys_storage_get_device_info(id, &disc_info);
    if(rr != 0)  {dev_sectsize[fd] = 512; return false;}

    dev_sectsize[fd]  = disc_info.sector_size;

    if(dev_fd[fd] >= 0) return true;

    if(sys_storage_open(id, &dev_fd[fd])<0) {dev_fd[fd] = -1; return false;}

    dev_sectsize[fd] = disc_info.sector_size;

	return true; // ok
	
}

bool PS3_NTFS_Shutdown(int fd)
{
    if(fd < 0 || fd > 7) return false;

    if(dev_fd[fd] < 0) return false;

    sys_storage_close(dev_fd[fd]);
    
    dev_fd[fd] = -1;
   
	return true;
}

bool PS3_NTFS_ShutdownA(int fd)
{
    if(fd < 0 || fd > 7) return false;
    
    return true;
}

bool PS3_NTFS_ReadSectors(int fd, sec_t sector, sec_t numSectors, void* buffer)
{
    int flag = ((int) (s64) buffer) & 31;

    if(dev_fd[fd] < 0 || !buffer) return false;

    void *my_buff;
    
    if(flag) my_buff = memalign(16, dev_sectsize[fd] * numSectors); else my_buff = buffer;

    uint32_t sectors_read;

    if(!my_buff) return false;

    int n;
    int r;

    for(n = 0; n < 8; n++) {

        r = sys_storage_read(dev_fd[fd], (uint32_t) sector, (uint32_t) numSectors, 
            (uint8_t *) my_buff, &sectors_read); 

        if(r == 0x80010002) {PS3_NTFS_Shutdown(fd);}

        if(r == 0) break;
        usleep(62500);
    }

    if(flag) {
       if(r>=0) memcpy(buffer, my_buff, dev_sectsize[fd] * numSectors);

        free(my_buff);
    }

    if(r < 0) return false;

    if(sectors_read != numSectors) return false;

    return true;
		
}

bool PS3_NTFS_WriteSectors(int fd, sec_t sector, sec_t numSectors,const void* buffer)
{

    int flag = ((int) (s64) buffer) & 31;

    if(dev_fd[fd] < 0  || !buffer) return false;

    void *my_buff;
    
    if(flag) my_buff = memalign(32, dev_sectsize[fd] * numSectors); else my_buff = (void *) buffer;

    uint32_t sectors_read;

    if(!my_buff) return false;
    
    if(flag) memcpy(my_buff, buffer, dev_sectsize[fd] * numSectors);

    int n;
    int r;

    for(n = 0; n < 8; n++) {

        r = sys_storage_write(dev_fd[fd], (uint32_t) sector, (uint32_t) numSectors, 
        (uint8_t *) my_buff, &sectors_read);

        if(r == 0x80010002) {PS3_NTFS_Shutdown(fd); break;}
        if(r == 0) break;
        usleep(62500);
    }


    if(flag) free(my_buff);

    if(r < 0) return false;

    if(sectors_read != numSectors) return false;

    return true;
		
}

bool PS3_NTFS_ClearStatus()
{
	return true;
}
 
static bool PS3_NTFS_IsInsertedA(int fd)
{
    return true;
}

bool PS3_NTFS_IsInserted(int fd)
{
    int r;
    u64 id = 0x010300000000000AULL;
    device_info_t disc_info;

    if(fd < 0 || fd > 7) return false;

    id+= (u64) (fd + 0xF * (fd >=6));
    
    disc_info.unknown03 = 0x12345678; // hack for Iris Manager Disc Less
    r=sys_storage_get_device_info(id, &disc_info);
    
    if(r < 0) {
        if(r == 0x80010002) {PS3_NTFS_Shutdown(fd);}
        return false;
    }

	return true;
}

bool PS3_NTFS_Startup1()
{
    return PS3_NTFS_Startup(0x010300000000000AULL, 0);
}

bool PS3_NTFS_Startup2()
{
    return PS3_NTFS_Startup(0x010300000000000BULL, 1);
}

bool PS3_NTFS_Startup3()
{
    return PS3_NTFS_Startup(0x010300000000000CULL, 2);
}

bool PS3_NTFS_Startup4()
{
    return PS3_NTFS_Startup(0x010300000000000DULL, 3);
}

bool PS3_NTFS_Startup5()
{
    return PS3_NTFS_Startup(0x010300000000000EULL, 4);
}

bool PS3_NTFS_Startup6()
{
    return PS3_NTFS_Startup(0x010300000000000FULL, 5);
}

bool PS3_NTFS_Startup7()
{
    return PS3_NTFS_Startup(0x010300000000001FULL, 6);
}

bool PS3_NTFS_Startup8()
{
    return PS3_NTFS_Startup(0x0103000000000020ULL, 7);
}

bool PS3_NTFS_IsInserted1()
{
	return PS3_NTFS_IsInsertedA(0);
}

bool PS3_NTFS_IsInserted2()
{
	return PS3_NTFS_IsInsertedA(1);
}

bool PS3_NTFS_IsInserted3()
{
	return PS3_NTFS_IsInsertedA(2);
}

bool PS3_NTFS_IsInserted4()
{
	return PS3_NTFS_IsInsertedA(3);
}

bool PS3_NTFS_IsInserted5()
{
	return PS3_NTFS_IsInsertedA(4);
}

bool PS3_NTFS_IsInserted6()
{
	return PS3_NTFS_IsInsertedA(5);
}

bool PS3_NTFS_IsInserted7()
{
	return PS3_NTFS_IsInsertedA(6);
}

bool PS3_NTFS_IsInserted8()
{
	return PS3_NTFS_IsInsertedA(7);
}

bool PS3_NTFS_Shutdown1()
{
    return PS3_NTFS_ShutdownA(0);
}

bool PS3_NTFS_Shutdown2()
{
    return PS3_NTFS_ShutdownA(1);
}

bool PS3_NTFS_Shutdown3()
{
    return PS3_NTFS_ShutdownA(2);
}

bool PS3_NTFS_Shutdown4()
{
    return PS3_NTFS_ShutdownA(3);
}

bool PS3_NTFS_Shutdown5()
{
    return PS3_NTFS_ShutdownA(4);
}

bool PS3_NTFS_Shutdown6()
{
    return PS3_NTFS_ShutdownA(5);
}

bool PS3_NTFS_Shutdown7()
{
    return PS3_NTFS_ShutdownA(6);
}

bool PS3_NTFS_Shutdown8()
{
    return PS3_NTFS_ShutdownA(7);
}

bool PS3_NTFS_ReadSectors1(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(0, sector, numSectors, buffer);
}

bool PS3_NTFS_ReadSectors2(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(1, sector, numSectors, buffer);
}

bool PS3_NTFS_ReadSectors3(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(2, sector, numSectors, buffer);
}

bool PS3_NTFS_ReadSectors4(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(3, sector, numSectors, buffer);
}

bool PS3_NTFS_ReadSectors5(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(4, sector, numSectors, buffer);
}

bool PS3_NTFS_ReadSectors6(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(5, sector, numSectors, buffer);
}

bool PS3_NTFS_ReadSectors7(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(6, sector, numSectors, buffer);
}

bool PS3_NTFS_ReadSectors8(sec_t sector, sec_t numSectors, void* buffer)
{
    return PS3_NTFS_ReadSectors(7, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors1(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(0, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors2(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(1, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors3(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(2, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors4(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(3, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors5(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(4, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors6(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(5, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors7(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(6, sector, numSectors, buffer);
}

bool PS3_NTFS_WriteSectors8(sec_t sector, sec_t numSectors,const void* buffer)
{
    return PS3_NTFS_WriteSectors(7, sector, numSectors, buffer);
}


#define DEVICE_TYPE_NTFS1 (('U'<<24)|('S'<<16)|('B'<<8)|'0')
#define DEVICE_TYPE_NTFS2 (('U'<<24)|('S'<<16)|('B'<<8)|'1')
#define DEVICE_TYPE_NTFS3 (('U'<<24)|('S'<<16)|('B'<<8)|'2')
#define DEVICE_TYPE_NTFS4 (('U'<<24)|('S'<<16)|('B'<<8)|'3')
#define DEVICE_TYPE_NTFS5 (('U'<<24)|('S'<<16)|('B'<<8)|'4')
#define DEVICE_TYPE_NTFS6 (('U'<<24)|('S'<<16)|('B'<<8)|'5')
#define DEVICE_TYPE_NTFS7 (('U'<<24)|('S'<<16)|('B'<<8)|'6')
#define DEVICE_TYPE_NTFS8 (('U'<<24)|('S'<<16)|('B'<<8)|'7')


const DISC_INTERFACE __io_ntfs_usb000 = {
    DEVICE_TYPE_NTFS1,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup1,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted1,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors1,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors1,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown1
};

const DISC_INTERFACE __io_ntfs_usb001 = {
    DEVICE_TYPE_NTFS2,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup2,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted2,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors2,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors2,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown2
};

const DISC_INTERFACE __io_ntfs_usb002 = {
    DEVICE_TYPE_NTFS3,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup3,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted3,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors3,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors3,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown3
};

const DISC_INTERFACE __io_ntfs_usb003 = {
    DEVICE_TYPE_NTFS4,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup4,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted4,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors4,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors4,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown4
};

const DISC_INTERFACE __io_ntfs_usb004 = {
    DEVICE_TYPE_NTFS5,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup5,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted5,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors5,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors5,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown5
};

const DISC_INTERFACE __io_ntfs_usb005 = {
    DEVICE_TYPE_NTFS6,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup6,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted6,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors6,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors6,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown6
};

const DISC_INTERFACE __io_ntfs_usb006 = {
    DEVICE_TYPE_NTFS7,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup7,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted7,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors7,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors7,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown7
};
 
const DISC_INTERFACE __io_ntfs_usb007 = {
    DEVICE_TYPE_NTFS8,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_PS3_USB,
    (FN_MEDIUM_STARTUP)&PS3_NTFS_Startup8,
	(FN_MEDIUM_ISINSERTED)&PS3_NTFS_IsInserted8,
	(FN_MEDIUM_READSECTORS)&PS3_NTFS_ReadSectors8,
	(FN_MEDIUM_WRITESECTORS)&PS3_NTFS_WriteSectors8,
	(FN_MEDIUM_CLEARSTATUS)&PS3_NTFS_ClearStatus,
	(FN_MEDIUM_SHUTDOWN)&PS3_NTFS_Shutdown8
};

#include <sys/errno.h>
#include "ntfsfile.h"
#include "ntfsdir.h"

static struct _reent reent1;

static int _init = 0;
#define MAX_LEVELS 32

static int my_files[MAX_LEVELS];
static ntfs_file_state file_state[MAX_LEVELS];

static void ps3ntfs_init()
{
    int n;

    if (_init) return;

    for(n = 0; n < MAX_LEVELS; n++) my_files[n] = 0;

    _init = 1;
}

static int get_dev(int fd)
{
    int n;

    if(fd <= 0) return 1;

    ntfs_file_state* file = (void *) (s64) fd;
    
    for(n = 0; n < 33; n++) {
        if(devoptab_list[n])  {
           if(file->is_ntfs && !strncmp("ntfs", devoptab_list[n]->name, 4)) return n;
           if(!file->is_ntfs && !strncmp("ext", devoptab_list[n]->name, 3)) return n;
        }
      
    }

    return 1;
}

static int get_dev2(const char *name)
{
    int n;

    
    for(n = 0; n < 33; n++) {
        if(devoptab_list[n])  {
           if(!strncmp(name, devoptab_list[n]->name, strlen(devoptab_list[n]->name))) return n;
        }
      
    }

    return 1;
}

int ps3ntfs_open(const char *path, int flags, int mode) 
{
    int n = 1, m, ret;

    int is_ntfs = 0; 
    if(!strncmp(path, "ntfs", 4) || !strncmp(path, "/ntfs", 5) ||
       !strncmp(path, "ext", 3) || !strncmp(path, "/ext", 4)) is_ntfs = 1;

    reent1._errno = 0;

    ps3ntfs_init();

    if(is_ntfs) {

        if(path[0]=='/') path++;

        for(n = 0; n < 33; n++) {
            if(devoptab_list[n])  { 
               if(!strncmp(path, devoptab_list[n]->name, strlen(devoptab_list[n]->name))) break;
            }
          
        }

        if(n == 33) return -1;
    }

    for(m = 0; m < MAX_LEVELS; m++) if(my_files[m] == 0) break;
    
    if(m == MAX_LEVELS) return -1;

    my_files[m] = 1;

    memset((void *) &file_state[m], 0, sizeof(ntfs_file_state));

    if(!is_ntfs) {
        int flag = flags&(O_ACCMODE|SYS_O_MSELF);
        int fd;

        if(flags&O_CREAT)
            flag |= SYS_O_CREAT;
        if(flags&O_TRUNC)
            flag |= SYS_O_TRUNC;
        if(flags&O_EXCL)
            flag |= SYS_O_EXCL;
        if(flags&O_APPEND)
            flag |= SYS_O_APPEND;

        if(flags&O_CREAT)
            mode = UMASK(mode);
        else
            mode = 0;

        int ret = sysLv2FsOpen(path, flag,&fd,mode,NULL,0);

        if(ret < 0) {my_files[m] = 0; reent1._errno = ret; return ret;}

        if(flags&O_CREAT)
            sysLv2FsChmod(path,  FS_S_IFMT | mode);

        file_state[m].flags = 0x1000000 | (flag); // system device
        file_state[m].pos = fd;

        return (int) (s64) &file_state[m];
    }
    
    ret = devoptab_list[n]->open_r(&reent1, (void *) &file_state[m], path, flags, mode);

    if(ret < 0) my_files[m] = 0;

   // ntfs_file_state* file = (void *) (s64) ret;
   // if(file->is_ntfs) DrawDialogOK("NTFS"); else DrawDialogOK("EXT");

    return ret;

}

int ps3ntfs_close(int fd) 
{

    if(fd < 0) return -1;
    
    reent1._errno = 0;

    int r;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    if(fs->flags & 0x1000000) { // is system device
        r = sysLv2FsClose(fs->pos);
        reent1._errno = r;
    } else 
        r = devoptab_list[get_dev(fd)]->close_r(&reent1, fd);

    int m;

    for(m = 0; m < 32; m++) 
        if(fd == ((int) (s64) &file_state[m]) && my_files[m]) {my_files[m] = 0;  break;}
    
    return r;

}

int ps3ntfs_write(int fd, const char *ptr, size_t len) 
{
    if(fd < 0) return -1;
    
    reent1._errno = 0;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    int r;

    if(fs->flags & 0x1000000) { // is system device
        u64 by;
        r = sysLv2FsWrite(fs->pos, (const void*) ptr, len, &by);
        if(r>=0) r = (int) by; else reent1._errno = r;
        return r;
    }

    return devoptab_list[get_dev(fd)]->write_r(&reent1, fd, ptr, len);

}

int ps3ntfs_read(int fd, char *ptr, size_t len) 
{
    if(fd < 0) return -1;

    reent1._errno = 0;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    int r;

    if(fs->flags & 0x1000000) { // is system device
        u64 by;
        r = sysLv2FsRead(fs->pos, (void*) ptr, len, &by);
        if(r>=0) r = (int) by; else reent1._errno = r;
        return r;
    }

    return devoptab_list[get_dev(fd)]->read_r(&reent1, fd, ptr, len);

}

off_t  ps3ntfs_seek(int fd, off_t pos, int dir) 
{
    if(fd < 0) return -1;

    reent1._errno = 0;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    int r;

    if(fs->flags & 0x1000000) { // is system device
        u64 by;
        
        r = sysLv2FsLSeek64(fs->pos, (s64) pos, dir, &by);
        if(r>=0) r = (int) by; else reent1._errno = r;
        return r;
    }

    return devoptab_list[get_dev(fd)]->seek_r(&reent1, fd, pos, dir);

}

s64  ps3ntfs_seek64(int fd, s64 pos, int dir) 
{
    if(fd < 0) return -1;

    reent1._errno = 0;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    s64 r;

    if(fs->flags & 0x1000000) { // is system device
        u64 by;
        
        r = sysLv2FsLSeek64(fs->pos, (s64) pos, dir, &by);
        if(r>=0) r = (int) by; else reent1._errno = r;
        return r;
    }

    return devoptab_list[get_dev(fd)]->seek64_r(&reent1, fd, pos, dir);

}

static void convertLv2Stat(struct stat *dst,sysFSStat *src)
{
	memset(dst,0,sizeof(struct stat));
	dst->st_mode = src->st_mode;
	dst->st_uid = src->st_uid;
	dst->st_gid = src->st_gid;
	dst->st_atime = src->st_atime;
	dst->st_mtime = src->st_mtime;
	dst->st_ctime = src->st_ctime;
	dst->st_size = src->st_size;
	dst->st_blksize = src->st_blksize;

}

int ps3ntfs_fstat(int fd, struct stat *st) 
{
    if(fd < 0) return -1;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    int r;

    if(fs->flags & 0x1000000) { // is system device
        
        sysFSStat stat;

	    r = sysLv2FsFStat(fs->pos,&stat);
	    if(!r && st) convertLv2Stat(st,&stat);
        reent1._errno = r;
        return r;
    }
    
    reent1._errno = 0;

    return devoptab_list[get_dev(fd)]->fstat_r(&reent1, fd, st);

}

int ps3ntfs_stat(const char *file, struct stat *st) 
{
    if(strncmp(file, "ntfs", 4) && strncmp(file, "/ntfs", 5) && 
        strncmp(file, "ext", 3) && strncmp(file, "/ext", 4)) { // file system
        int r;
        sysFSStat stat;

	    r = sysLv2FsStat(file,&stat);
	    if(!r && st) convertLv2Stat(st,&stat);
        reent1._errno = r;
        return r;
    }

    
    reent1._errno = 0;

    if(file[0]=='/') file++;

    return devoptab_list[get_dev2(file)]->stat_r(&reent1, file, st);

}

int ps3ntfs_link(const char *existing, const char  *newLink) 
{
    if(strncmp(newLink, "ntfs", 4) && strncmp(newLink, "/ntfs", 5) && 
        strncmp(newLink, "ext", 3) && strncmp(newLink, "/ext", 4)) { // file system
        int r;

	    r = sysLv2FsLink(existing, newLink);
        reent1._errno = r;
        return r;
    }
    
    reent1._errno = 0;

    if(existing[0]=='/') existing++;
    if(newLink[0]=='/') newLink++;

    return devoptab_list[get_dev2(newLink)]->link_r(&reent1, existing, newLink);

}

int ps3ntfs_unlink(const char *name) 
{
    if(strncmp(name, "ntfs", 4) && strncmp(name, "/ntfs", 5) && 
        strncmp(name, "ext", 3) && strncmp(name, "/ext", 4)) { // file system
        int r;

        sysFSStat stat;

	    r = sysLv2FsStat(name,&stat);
        reent1._errno = r;
        if(r < 0) return r;
         
        if (S_ISDIR(stat.st_mode)) r = sysLv2FsRmdir(name);
	    r = sysLv2FsUnlink(name);
        reent1._errno = r;
        return r;
    }
    
    reent1._errno = 0;

    if(name[0]=='/') name++;

    return devoptab_list[get_dev2(name)]->unlink_r(&reent1, name);

}


int ps3ntfs_chdir(const char *name) 
{
   // NOTE: unsupported because the PS3 support is thinking in absolute paths
    #if 0
    if(strncmp(name, "ntfs", 4) && strncmp(name, "/ntfs", 5) && 
        strncmp(name, "ext", 3) && strncmp(name, "/ext", 4)) { // file system
       
        return -1;
    }
    
    reent1._errno = 0;

    if(name[0]=='/') name++;

    return devoptab_list[get_dev2(name)]->chdir_r(&reent1, name);
    #endif
    return -1;

}

int ps3ntfs_rename(const char *oldName, const char *newName) 
{
    if(strncmp(newName, "ntfs", 4) && strncmp(newName, "/ntfs", 5) && 
        strncmp(newName, "ext", 3) && strncmp(newName, "/ext", 4)) { // file system
        int r;

	    r = sysLv2FsRename(oldName, newName);
        reent1._errno = r;
        return r;
    }
    
    reent1._errno = 0;

    if(oldName[0]=='/') oldName++;
    if(newName[0]=='/') newName++;

    return devoptab_list[get_dev2(newName)]->rename_r(&reent1, oldName, newName);

}

int ps3ntfs_mkdir(const char *path, int mode) 
{
    if(strncmp(path, "ntfs", 4) && strncmp(path, "/ntfs", 5) && 
        strncmp(path, "ext", 3) && strncmp(path, "/ext", 4)) { // file system
        int r;

	    r = sysLv2FsMkdir(path, UMASK(mode));
        reent1._errno = r;
        return r;
    }
    
    reent1._errno = 0;

    if(path[0]=='/') path++;

    return devoptab_list[get_dev2(path)]->mkdir_r(&reent1, path, mode);

}
struct dopendir {
    s32 fd;
    char path[1024];
};

DIR_ITER*  ps3ntfs_diropen(const char *path) 
{
    int n = 1;

    if(strncmp(path, "ntfs", 4) && strncmp(path, "/ntfs", 5) && 
        strncmp(path, "ext", 3) && strncmp(path, "/ext", 4)) { // file system
        int r;
        s32 fd;

        r = sysLv2FsOpenDir(path, &fd);

        if(r == 0) {
            
            DIR_ITER *dirState = malloc(sizeof(struct dopendir) + ((sizeof(DIR_ITER) + 15) & ~15));

            if(!dirState) {sysLv2FsCloseDir(fd); return NULL;}

            reent1._errno = 0;

            memset((void *) dirState, 0, sizeof(struct dopendir)   + ((sizeof(DIR_ITER) + 15) & ~15));

            dirState->device = 0x1000000;
            dirState->dirStruct = (void*) (((char *) dirState) + ((sizeof(DIR_ITER) + 15) & ~15));
            struct dopendir * dopen = dirState->dirStruct;
            dopen->fd = fd;
            strcpy(dopen->path, path); strcat(dopen->path, "/");
            
            return dirState;

        }

        reent1._errno = r;
        return NULL;
    }

    if(path[0]=='/') path++;

    for(n = 0; n < 33; n++) {
        if(devoptab_list[n])  { 
           if(!strncmp(path, devoptab_list[n]->name, strlen(devoptab_list[n]->name))) break;
        }
      
    }

    if(n == 33) return NULL;


    DIR_ITER *dirState = malloc(devoptab_list[n]->dirStateSize + ((sizeof(DIR_ITER) + 15) & ~15));


    if(!dirState) return NULL;

    memset((void *) dirState, 0, devoptab_list[n]->dirStateSize  + ((sizeof(DIR_ITER) + 15) & ~15));

    dirState->dirStruct = (void*) (((char *) dirState) + ((sizeof(DIR_ITER) + 15) & ~15));
    dirState->device = n;

    reent1._errno = 0;

    return devoptab_list[n]->diropen_r(&reent1, (void *) dirState, path);

}

int ps3ntfs_dirreset(DIR_ITER *dirState) 
{
  
    if(!dirState) return -1;

    reent1._errno = 0;

    if(dirState->device & 0x1000000) {
        return -1;
    } 

    return devoptab_list[dirState->device]->dirreset_r(&reent1, dirState);

}

int ps3ntfs_dirnext(DIR_ITER *dirState, char *filename, struct stat *filestat) 
{
    if(!dirState) return -1;

    reent1._errno = 0;

    int r;

    if(dirState->device & 0x1000000) {
        struct dopendir * dopen = dirState->dirStruct;

        sysFSDirent entry;
        u64 read = 0;

        r = sysLv2FsReadDir(dopen->fd, &entry, &read);
        if(read == 0) r = -1;
        reent1._errno = r;
        
        if(r == 0) {
            memcpy(filename, entry.d_name, entry.d_namlen);
            filename[entry.d_namlen]= 0;

            if(filestat) {

                if(strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
                    memset(filestat, 0, sizeof(struct stat));
                    filestat->st_mode = S_IFDIR;
                } else {
                    int n= strlen(dopen->path);
                    memset(filestat, 0, sizeof(struct stat));
                    strcat(dopen->path, (char *) filename);
                    ps3ntfs_stat((const char *) dopen->path, filestat);

                    dopen->path[n] = 0;
                }
            }    
        }
        return r;
    }

    return devoptab_list[dirState->device]->dirnext_r(&reent1, dirState, filename, filestat);

}

int ps3ntfs_dirclose(DIR_ITER *dirState) 
{
    if(!dirState) return -1;

    reent1._errno = 0;

    int r;

    if(dirState->device & 0x1000000) {
        struct dopendir * dopen = dirState->dirStruct;

        r = sysLv2FsCloseDir(dopen->fd);
        reent1._errno = r;
    } else 
        r = devoptab_list[dirState->device]->dirclose_r(&reent1, dirState);

    free(dirState); dirState = NULL;

    return r;

}


int ps3ntfs_statvfs(const char *path, struct statvfs *buf) 
{
    reent1._errno = 0;

    if(strncmp(path, "ntfs", 4) && strncmp(path, "/ntfs", 5) && 
        strncmp(path, "ext", 3) && strncmp(path, "/ext", 4)) { // file system
       
        return -1;
    }

    if(path[0]=='/') path++;
  
    return devoptab_list[get_dev2(path)]->statvfs_r(&reent1, path, buf);

}

int ps3ntfs_ftruncate(int fd, off_t len) 
{
    if(fd < 0) return -1;

    reent1._errno = 0;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    int r;

    if(fs->flags & 0x1000000) { // is system device
        
	    r= sysLv2FsFtruncate(fs->pos, (u64) len);
        reent1._errno = r;
        return r;
    }

    return devoptab_list[get_dev(fd)]->ftruncate_r(&reent1, fd, len);

}

int ps3ntfs_fsync(int fd) 
{
    if(fd < 0) return -1;
    
    reent1._errno = 0;

    ntfs_file_state *fs = (ntfs_file_state *) (s64) fd;

    int r;

    if(fs->flags & 0x1000000) { // is system device

	    r = sysLv2FsFsync(fs->pos);
	    reent1._errno = r;
        return r;
    }

    return devoptab_list[get_dev(fd)]->fsync_r(&reent1, fd);

}

int ps3ntfs_errno(void)
{
    return reent1._errno;
}

#endif