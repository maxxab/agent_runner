/* Isolated B fixture: exact temporary A check/bind seams, all input syscalls mocked.
 * Actual clock/launch integration is separately mandatory; never a qualification entry. */
#define _GNU_SOURCE
#define RNR_STAGE0_PRIVATE_QUALIFICATION 1
#ifdef NDEBUG
#error "Preparer fixtures require active assertions"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <poll.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_preparer.h"
#include "../../automation/native/runtime_stage0_bootstrap.h"
#include "../../automation/native/runtime_stage0_project_view.h"
#include "test_runtime_stage0_policy_inputs.h"
#include "test_runtime_stage0_manager_vectors.h"
#include "test_runtime_stage0_cgroup_model.h"
#include "test_runtime_stage0_mountinfo_model.h"
#include "test_runtime_stage0_search_path_model.h"
/* Never send simulated descriptors to host operations outside this fixture. */
_Noreturn void __wrap_fcntl(void){abort();}
_Noreturn void __wrap_ioctl(void){abort();}
static int executable_live[19],executable_closes[19];
static int unit_live[10],unit_closes[10],unit_tamper_role,unit_open_role;
static int unit_identity_role,unit_mount_role,unit_named_role,unit_bad_mode_role,unit_eof_role,unit_short_role;
static int unit_stat_calls[10],unit_mount_calls[10],unit_change_after_bind;
static int unit_bad_uid_role,unit_bad_gid_role,unit_negative_size_role,unit_read_error_role,large_unit,unit_late_kind;
static unsigned char large_unit_bytes[65536];
_Static_assert(sizeof(off_t)==8 && (off_t)-1<0 && SIZE_MAX>=INT64_MAX,
               "supported fixture represents every nonnegative off_t in size_t");
static int executable_tamper_fd,executable_header_fd,executable_size_fd,executable_mode_fd;
static int executable_xattr_fd,executable_xattr_kind,executable_read_error_fd,executable_eof_fd,executable_open_role;
static int executable_identity_fd,executable_mount_fd,executable_stat_calls[19],executable_mount_calls[19];
static int large_native,executable_late_fd,executable_late_kind,peer_dead_after_bind,held_binds;
static unsigned char large_native_bytes[65536];
static const char large_native_hash[]="c6a548564edd8c4d347f72f5873ca794cf8f3673de39889ed4c516c0f7aa2d40";
static int error_seen;
static int executable_role(int fd)
{return fd>=80?(fd==82?18:16):11+(fd-64)%8;}
ssize_t __wrap_fgetxattr(int fd,const char *name,void *value,size_t size)
{
    assert(fd>=64&&fd<=82&&executable_live[fd-64]&&!strcmp(name,"security.capability")&&!value&&!size);
    assert(executable_role(fd)==16||executable_role(fd)==18);
    if(fd==executable_xattr_fd){error_seen=1;if(executable_xattr_kind==1)return 0;errno=EOPNOTSUPP;return -1;}
    errno=ENODATA;return -1;
}
static int project_captures,project_checks,project_closes,project_bad,seen_exec_mask,seen_unit_mask,cwd_checks,bad_cwd,manager_auth_done;
static int manager_live,manager_path_live[3],manager_phase,manager_close_count,manager_case,manager_peer_calls,manager_recv_offset,manager_stat_calls[3],manager_lookup_done,manager_auth_eagain;
static int manager_drift_role,manager_drift_kind;
static void fixture_drift_policy(unsigned int role);
static unsigned char manager_reply[146];static size_t manager_reply_offset;
static unsigned char manager_property_reply[1024];
static size_t manager_property_offset,manager_property_length;static int manager_property_done,manager_property_eagain;
static int manager_unit_ids,manager_id_eagain,manager_unit_names,manager_names_eagain,manager_unit_fields,manager_unit_bools,manager_unit_facts,manager_unit_dependencies,manager_unit_timeouts,manager_service_fields,manager_service_scalars,manager_service_empty,manager_service_exec,manager_cgroup_strings,manager_cgroup_scalars,manager_cgroup_arrays,manager_cgroup_ids,manager_sends;
int __wrap_poll(struct pollfd *fds,nfds_t count,int timeout)
{assert(count==1&&fds->fd==110&&manager_live&&timeout==1&&(fds->events==POLLIN||fds->events==POLLOUT));
 if(manager_case==44){errno=EINTR;return -1;}if(manager_case==45)return 0;
 fds->revents=manager_case==46?POLLHUP:fds->events;return 1;}
int __wrap_socket(int domain,int type,int protocol)
{assert(domain==AF_UNIX&&type==(SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC)&&protocol==0&&!manager_live);
 if(manager_case==2){errno=EMFILE;return -1;}manager_live=1;return 110;}
int __wrap_connect(int fd,const struct sockaddr *address,socklen_t length)
{const struct sockaddr_un *u=(const struct sockaddr_un *)address;assert(fd==110&&manager_live&&u->sun_family==AF_UNIX&&
 !strcmp(u->sun_path,"/run/systemd/private")&&length==offsetof(struct sockaddr_un,sun_path)+sizeof("/run/systemd/private"));
 if(manager_case==3||manager_case==39||(manager_case>=43&&manager_case<=46)){errno=EINPROGRESS;return -1;}if(manager_case==4){errno=ECONNREFUSED;return -1;}return 0;}
int __wrap_setsockopt(int fd,int level,int option,const void *value,socklen_t length)
{assert(fd==110&&manager_live&&level==SOL_SOCKET&&(option==SO_PASSCRED||option==SO_PASSSEC)&&length==sizeof(int)&&*(const int *)value==0);
 if(manager_case==40){error_seen=1;errno=EIO;return -1;}return 0;}
int __wrap_getsockopt(int fd,int level,int option,void *value,socklen_t *length)
{assert(fd==110&&manager_live&&level==SOL_SOCKET);if(option==SO_PEERCRED){assert(*length==sizeof(struct ucred));
 ++manager_peer_calls;*(struct ucred *)value=(struct ucred){.pid=(manager_case==1||(manager_case==12&&manager_peer_calls>=2)||(manager_case==47&&manager_lookup_done)||(manager_case==48&&held_binds))?2:1,.uid=0,.gid=0};return 0;}
 assert((option==SO_PASSCRED||option==SO_PASSSEC||option==SO_ERROR)&&*length==sizeof(int));
 *(int *)value=(manager_case==5&&option==SO_PASSCRED)?1:(manager_case==39&&option==SO_ERROR)?ECONNREFUSED:0;return 0;}
ssize_t __wrap_send(int fd,const void *buffer,size_t length,int flags)
{static const char auth[]="\0AUTH EXTERNAL 30\r\n",begin[]="BEGIN\r\n";
 assert(fd==110&&manager_live&&flags==MSG_NOSIGNAL);
 if(manager_case==6)return (ssize_t)length-1;
 if(!manager_phase){assert(length==sizeof(auth)-1&&!memcmp(buffer,auth,length));manager_phase=1;}
 else{assert(manager_phase==2&&length==sizeof(begin)-1&&!memcmp(buffer,begin,length));manager_phase=3;manager_auth_done=1;}
 return (ssize_t)length;}
ssize_t __wrap_sendmsg(int fd,const struct msghdr *message,int flags)
{
 assert(fd==110&&manager_live&&flags==MSG_NOSIGNAL&&message->msg_iovlen==1&&
        !message->msg_control&&!message->msg_controllen);
 ++manager_sends;
 if((manager_phase==19&&manager_cgroup_arrays==8&&manager_property_offset==manager_property_length)||
    (manager_phase==20&&manager_property_offset==manager_property_length)){
  assert(manager_cgroup_ids<4);unsigned int role=(unsigned)manager_cgroup_ids;
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service","ControlGroupId",273+manager_cgroup_ids);
  manager_property_length=fixture_cgroup_id_reply(manager_property_reply,role);
  if(manager_case==610+manager_cgroup_ids)memset(manager_property_reply+40,0,8);
  if(manager_case==614)manager_property_reply[33]='u';
  if(manager_case==615)manager_property_reply[39]=1;
  if(manager_case==616)--manager_property_reply[4];
  if(manager_case==617)manager_property_reply[20]^=1;
  if(manager_case==618)manager_property_reply[35]=1;
  manager_property_offset=0;manager_phase=20;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==18&&manager_cgroup_scalars==24&&manager_property_offset==manager_property_length)||
    (manager_phase==19&&manager_property_offset==manager_property_length)){
  assert(manager_cgroup_arrays<8);unsigned int field=(unsigned)manager_cgroup_arrays/4,role=(unsigned)manager_cgroup_arrays%4;
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service",fixture_cgroup_arrays[field],265+manager_cgroup_arrays);
  manager_property_length=fixture_cgroup_array_reply(manager_property_reply,field,role);
  if(manager_case==590+manager_cgroup_arrays){
   if(manager_property_length>40)manager_property_reply[44]^=1;
   else{manager_property_reply[4]=16;manager_property_reply[36]=8;manager_property_reply[40]=3;
    manager_property_reply[41]=manager_property_reply[42]=manager_property_reply[43]=0;
    memcpy(manager_property_reply+44,"bad",4);manager_property_length=48;}}
  if(manager_case==598)manager_property_reply[33]='u';
  if(manager_case==599)manager_property_reply[35]=1;
  if(manager_case==600)--manager_property_reply[36];
  if(manager_case==601)manager_property_reply[59]=1;
  if(manager_case==602)manager_property_reply[68]=1;
  if(manager_case==603)--manager_property_reply[40];
  if(manager_case==604)--manager_property_reply[4];
  if(manager_case==605){static const unsigned char reordered[]={6,0,0,0,'m','e','m','o','r','y',0,0,
      3,0,0,0,'c','p','u',0,4,0,0,0,'p','i','d','s',0};
   memcpy(manager_property_reply+40,reordered,sizeof(reordered));}
  manager_property_offset=0;manager_phase=19;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==17&&manager_cgroup_strings==20&&manager_property_offset==manager_property_length)||
    (manager_phase==18&&manager_property_offset==manager_property_length)){
  assert(manager_cgroup_scalars<24);unsigned int field=(unsigned)manager_cgroup_scalars/4,role=(unsigned)manager_cgroup_scalars%4;
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service",fixture_cgroup_scalars[field],241+manager_cgroup_scalars);
  /* Make just this policy slot differ after decode to prove per-role selection. */
  if(field==3&&manager_case==579+(int)role)fixture_drift_policy(role);
  manager_property_length=fixture_cgroup_scalar_reply(manager_property_reply,field,role,cg_distinct_policy);
  if(manager_case==550+manager_cgroup_scalars)manager_property_reply[field?40:36]^=1;
  if(manager_case==574)manager_property_reply[33]='s';
  if(manager_case==575)manager_property_reply[35]=1;
  if(manager_case==576)--manager_property_reply[4];
  if(manager_case==577&&field==1)manager_property_reply[39]=1;
  if(manager_case==578&&field==0)manager_property_reply[36]=2;
  manager_property_offset=0;manager_phase=18;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==16&&manager_service_exec==1&&manager_property_offset==manager_property_length)||
    (manager_phase==17&&manager_property_offset==manager_property_length)){
  assert(manager_cgroup_strings<20);unsigned int field=(unsigned)manager_cgroup_strings/4,role=(unsigned)manager_cgroup_strings%4;
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service",fixture_cgroup_strings[field],221+manager_cgroup_strings);
  manager_property_length=fixture_cgroup_string_reply(manager_property_reply,field,role);
  if(manager_case==520+manager_cgroup_strings)manager_property_reply[40]^=1;
  if(manager_case==540)manager_property_reply[33]='u';
  if(manager_case==541)manager_property_reply[35]=1;
  if(manager_case==542)--manager_property_reply[36];
  if(manager_case==543)manager_property_reply[manager_property_length-1]=1;
  if(manager_case==544)--manager_property_reply[4];
  manager_property_offset=0;manager_phase=17;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if(manager_phase==15&&manager_service_empty==11&&manager_property_offset==manager_property_length){
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service","ExecStartEx",220);
  manager_property_length=fixture_service_exec_reply(manager_property_reply,99,large_native?large_native_hash:fixture_native_hash);
  if(manager_case==500)manager_property_reply[60]^=1;
  if(manager_case==501)manager_property_reply[168]^=1;
  if(manager_case==502)manager_property_reply[268]=1;
  if(manager_case==503)manager_property_reply[288]=1;
  if(manager_case==504)manager_property_reply[296]=1;
  if(manager_case==505)manager_property_reply[304]^=1;
  if(manager_case==506)manager_property_reply[308]=1;
  if(manager_case==507)manager_property_reply[312]=1;
  if(manager_case==508)manager_property_reply[33]='b';
  if(manager_case==509)manager_property_reply[49]=1;
  if(manager_case==510)--manager_property_reply[52];
  if(manager_case==511)--manager_property_reply[160];
  if(manager_case==512)--manager_property_reply[56];
  if(manager_case==513)--manager_property_reply[164];
  if(manager_case==514)--manager_property_reply[4];
  if(manager_case==515){++manager_property_reply[4];++manager_property_reply[52];manager_property_reply[316]=0;++manager_property_length;}
  if(manager_case==516){manager_property_reply[4]=32;manager_property_reply[5]=2;manager_property_reply[52]=8;manager_property_reply[53]=2;
   memcpy(manager_property_reply+316,manager_property_reply+56,260);manager_property_length=576;}
  if(manager_case==517)manager_property_reply[268]=2;
  if(manager_case==518)manager_property_reply[159]=1;
  if(manager_case==519)manager_property_reply[267]=1;
  manager_property_offset=0;manager_phase=16;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==14&&manager_service_scalars==14&&manager_property_offset==manager_property_length)||
    (manager_phase==15&&manager_property_offset==manager_property_length)){
  assert(manager_service_empty<11);
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service",fixture_service_empty_names[manager_service_empty],(unsigned)(209+manager_service_empty));
  manager_property_length=fixture_service_empty_reply(manager_property_reply,(unsigned)manager_service_empty);
  if(manager_case==470+manager_service_empty)manager_property_reply[manager_property_length-1]=1;
  if(manager_case==481)manager_property_reply[33]='u';
  if(manager_case==482&&manager_service_empty==1)manager_property_reply[39]=1;
  if(manager_case==483&&manager_service_empty==4)manager_property_reply[40]=1;
  if(manager_case==484&&manager_service_empty==5)manager_property_reply[33]='b';
  if(manager_case==485&&manager_service_empty==5)manager_property_reply[49]=1;
  manager_property_offset=0;manager_phase=15;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==13&&manager_service_fields==20&&manager_property_offset==manager_property_length)||
    (manager_phase==14&&manager_property_offset==manager_property_length)){
  assert(manager_service_scalars<14);
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service",fixture_service_scalar_names[manager_service_scalars],(unsigned)(195+manager_service_scalars));
  manager_property_length=fixture_service_scalar_reply(manager_property_reply,(unsigned)manager_service_scalars,99);
  if(manager_case==430+manager_service_scalars)manager_property_reply[manager_service_scalars>=4&&manager_service_scalars<9?40:36]^=1;
  if(manager_case==444)manager_property_reply[33]='s';
  if(manager_case==445)manager_property_reply[35]=1;
  if(manager_case==446)--manager_property_reply[4];
  if(manager_case==447)manager_property_reply[36]=2;
  if(manager_case==448&&manager_service_scalars==4)manager_property_reply[47]=0x7f;
  if(manager_case==449&&manager_service_scalars==4)manager_property_reply[33]='u';
  if(manager_case==450&&manager_service_scalars==9)manager_property_reply[33]='b';
  if(manager_case==451&&manager_service_scalars==4)manager_property_reply[39]=1;
  if(manager_case==452&&manager_service_scalars==9)manager_property_reply[35]=1;
  if(manager_case==453&&manager_service_scalars==9)manager_property_reply[39]=1;
  manager_property_offset=0;manager_phase=14;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==12&&manager_unit_timeouts==8&&manager_property_offset==manager_property_length)||
    (manager_phase==13&&manager_property_offset==manager_property_length)){
  assert(manager_service_fields<20);
  fixture_check_property_interface(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service",fixture_service_field_names[manager_service_fields],(unsigned)(175+manager_service_fields));
  manager_property_length=fixture_service_field_reply(manager_property_reply,(unsigned)manager_service_fields);
  if(manager_case==360+manager_service_fields)manager_property_reply[40]^=1;
  if(manager_case==380)manager_property_reply[33]='u';
  if(manager_case==381)manager_property_reply[35]=1;
  if(manager_case==382)--manager_property_reply[36];
  if(manager_case==383)manager_property_reply[manager_property_length-1]=1;
  if(manager_case==384)--manager_property_reply[4];
  manager_property_offset=0;manager_phase=13;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==11&&manager_unit_dependencies==80&&manager_property_offset==manager_property_length)||
    (manager_phase==12&&manager_property_offset==manager_property_length)){
  assert(manager_unit_timeouts<8);unsigned int field=(unsigned)manager_unit_timeouts/4,role=(unsigned)manager_unit_timeouts%4;
  fixture_check_property(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
                         fixture_unit_timeout_names[field],(unsigned)(167+manager_unit_timeouts));
  manager_property_length=fixture_unit_timeout_reply(manager_property_reply,field,role);
  if(manager_case==330+manager_unit_timeouts)manager_property_reply[40]^=1;
  if(manager_case==338)manager_property_reply[33]='u';
  if(manager_case==339)manager_property_reply[39]=1;
  if(manager_case==340)manager_property_reply[4]=15;
  if(manager_case==341)manager_property_reply[47]=0x7f;
  manager_property_offset=0;manager_phase=12;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==10&&manager_unit_facts==8&&manager_property_offset==manager_property_length)||
    (manager_phase==11&&manager_property_offset==manager_property_length)){
  assert(manager_unit_dependencies<80);unsigned int field=(unsigned)manager_unit_dependencies/4,role=(unsigned)manager_unit_dependencies%4;
  fixture_check_property(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
                         fixture_unit_dependency_names[field],(unsigned)(87+manager_unit_dependencies));
  manager_property_length=fixture_unit_dependency_reply(manager_property_reply,field,role);
  if(manager_case==230+manager_unit_dependencies){
   if(manager_property_length==40){manager_property_reply[4]=16;manager_property_reply[36]=8;
    manager_property_reply[40]=3;manager_property_reply[41]=manager_property_reply[42]=manager_property_reply[43]=0;
    memcpy(manager_property_reply+44,"bad",4);manager_property_length=48;}
   else manager_property_reply[44]^=1;
  }
  if(manager_case==311)manager_property_reply[33]='u';
  if(manager_case==312)manager_property_reply[36]=1;
  if(field==1&&role==0&&manager_case==313)--manager_property_reply[40];
  if(field==1&&role==0&&manager_case==314)manager_property_reply[manager_property_length-1]=1;
  if(manager_case==315)manager_property_reply[4]=7;
  if(field==1&&role==0&&manager_case==316){size_t n=manager_property_reply[40];
   while(manager_property_length%4)manager_property_reply[manager_property_length++]=0;
   manager_property_reply[manager_property_length++]=(unsigned char)n;manager_property_reply[manager_property_length++]=0;
   manager_property_reply[manager_property_length++]=0;manager_property_reply[manager_property_length++]=0;
   memcpy(manager_property_reply+manager_property_length,manager_property_reply+44,n+1);manager_property_length+=n+1;
   manager_property_reply[4]=(unsigned char)(manager_property_length-32);manager_property_reply[36]=(unsigned char)(manager_property_length-40);}
  manager_property_offset=0;manager_phase=11;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==9&&manager_unit_bools==28&&manager_property_offset==manager_property_length)||
    (manager_phase==10&&manager_property_offset==manager_property_length)){
  assert(manager_unit_facts<8);unsigned int field=(unsigned)manager_unit_facts/4,role=(unsigned)manager_unit_facts%4;
  fixture_check_property(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
                         fixture_unit_fact_names[field],(unsigned)(79+manager_unit_facts));
  manager_property_length=fixture_unit_fact_reply(manager_property_reply,field,role);
  if(!field&&manager_case==200+(int)role)memset(manager_property_reply+40,0,16);
  if(field&&manager_case==204+(int)role)manager_property_reply[40]=1;
  if(field&&manager_case==208)manager_property_reply[48]='x';
  if(!field&&manager_case==209)manager_property_reply[33]='u';
  if(!field&&manager_case==210)manager_property_reply[36]=15;
  if(field&&manager_case==211)manager_property_reply[44]=2;
  if(field&&manager_case==212)manager_property_reply[33]='a';
  if(field&&manager_case==213)manager_property_reply[38]=1;
  if(field&&manager_case==214)manager_property_reply[32]=3;
  if(field&&manager_case==215)manager_property_reply[49]=1;
  manager_property_offset=0;manager_phase=10;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==8&&manager_unit_fields==40&&manager_property_offset==manager_property_length)||
    (manager_phase==9&&manager_property_offset==manager_property_length)){
  assert(manager_unit_bools<28);unsigned int field=(unsigned)manager_unit_bools/4,role=(unsigned)manager_unit_bools%4;
  fixture_check_property(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
                         fixture_unit_bool_names[field],(unsigned)(51+manager_unit_bools));
  manager_property_length=fixture_unit_bool_reply(manager_property_reply,field,role);
  if(manager_case==150+manager_unit_bools)manager_property_reply[36]^=1;
  if(manager_case==178)manager_property_reply[36]=2;
  if(manager_case==179)manager_property_reply[33]='u';
  if(manager_case==180)manager_property_reply[35]=1;
  if(manager_case==181)manager_property_reply[32]=2;
  if(manager_case==182)manager_property_reply[4]=7;
  manager_property_offset=0;manager_phase=9;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==7&&manager_unit_names==4&&manager_property_offset==manager_property_length)||
    (manager_phase==8&&manager_property_offset==manager_property_length)){
  assert(manager_unit_fields<40);unsigned int field=(unsigned)manager_unit_fields/4,role=(unsigned)manager_unit_fields%4;
  fixture_check_property(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,role,
                         fixture_unit_field_names[field],(unsigned)(11+manager_unit_fields));
  manager_property_length=fixture_unit_field_reply(manager_property_reply,field,role);
  if(manager_case==100+manager_unit_fields)manager_property_reply[40]^=1;
  manager_property_offset=0;manager_phase=8;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==6&&manager_unit_ids==4&&manager_property_offset==manager_property_length)||
    (manager_phase==7&&manager_property_offset==manager_property_length)){
  assert(manager_unit_names<4);fixture_check_property(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,
      (unsigned)manager_unit_names,"Names",(unsigned)(7+manager_unit_names));
  manager_property_length=fixture_names_reply(manager_property_reply,(unsigned)manager_unit_names);
  if(manager_case==79+manager_unit_names)manager_property_reply[44]^=1;
  if(manager_case==86)--manager_property_reply[36];
  if(manager_case==87)--manager_property_reply[40];
  if(manager_case==88)manager_property_reply[manager_property_length-1]=1;
  if(manager_case==89)manager_property_reply[33]='u';
  if(manager_case==90){unsigned char fields[]={8,1,'g',0,1,'v',0,0,5,1,'u',0,0,0,0,0};
   fields[12]=(unsigned char)(7+manager_unit_names);manager_property_reply[12]=16;memcpy(manager_property_reply+16,fields,sizeof(fields));}
  if(manager_case==83){while(manager_property_length%4)manager_property_reply[manager_property_length++]=0;
   manager_property_reply[manager_property_length++]=13;manager_property_reply[manager_property_length++]=0;
   manager_property_reply[manager_property_length++]=0;manager_property_reply[manager_property_length++]=0;
   memcpy(manager_property_reply+manager_property_length,"alias.service",14);manager_property_length+=14;
   manager_property_reply[4]=(unsigned char)(manager_property_length-32);manager_property_reply[36]=(unsigned char)(manager_property_length-40);}
  manager_property_offset=0;manager_phase=7;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if((manager_phase==5&&manager_property_done)||(manager_phase==6&&manager_property_offset==manager_property_length)){
  assert(manager_unit_ids<4);fixture_check_id(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,(unsigned)manager_unit_ids);
  manager_property_length=fixture_id_reply(manager_property_reply,(unsigned)manager_unit_ids);
  if(manager_case==66+manager_unit_ids)manager_property_reply[40]^=1;
  if(manager_case==70){unsigned char fields[]={8,1,'g',0,1,'v',0,0,5,1,'u',0,0,0,0,0};
   fields[12]=(unsigned char)(3+manager_unit_ids);manager_property_reply[12]=16;memcpy(manager_property_reply+16,fields,sizeof(fields));}
  if(manager_case==75)manager_property_reply[20]=1;
  if(manager_case==76)manager_property_reply[33]='u';
  if(manager_case==77)manager_property_reply[4]=255;
  if(manager_case==78)manager_property_reply[manager_property_length-1]=1;
  manager_property_offset=0;manager_phase=6;return (ssize_t)message->msg_iov[0].iov_len;
 }
 if(manager_phase==4&&manager_lookup_done){
  assert(message->msg_iov[0].iov_len==sizeof(fixture_unit_path_request)&&
         !memcmp(message->msg_iov[0].iov_base,fixture_unit_path_request,sizeof(fixture_unit_path_request)));
  memcpy(manager_property_reply,fixture_unit_path_reply,sizeof(fixture_unit_path_reply));
  manager_property_length=sizeof(fixture_unit_path_reply);
  if(manager_case==49)manager_property_reply[44]^=1;
  if(manager_case==50)manager_property_reply[33]='u';
  if(manager_case==51)manager_property_reply[20]=1;
  if(manager_case==52){manager_property_reply[4]=1;manager_property_reply[5]=64;}
  if(manager_case==53)manager_property_reply[4]=7;
  if(manager_case==54)--manager_property_reply[36];
  if(manager_case==55)manager_property_reply[67]=1;
  if(manager_case==56)manager_property_reply[91]=1;
  if(manager_case==57)manager_property_reply[72]^=1;
  if(manager_case==62){static const unsigned char fields[]={8,1,'g',0,1,'v',0,0,5,1,'u',0,2,0,0,0};
   manager_property_reply[12]=16;memcpy(manager_property_reply+16,fields,sizeof(fields));}
  if(manager_case==63){manager_property_reply[4]=35;manager_property_reply[36]=27;manager_property_length=67;}
  if(manager_case==64){manager_property_reply[4]=59;manager_property_reply[36]=51;
   manager_property_reply[40]=19;memcpy(manager_property_reply+44,"/etc/systemd/system",20);
   manager_property_reply[64]=22;manager_property_reply[65]=manager_property_reply[66]=manager_property_reply[67]=0;
   memcpy(manager_property_reply+68,"/run/systemd/transient",23);manager_property_length=91;}
  if(manager_case==65){manager_property_reply[4]=5;manager_property_reply[5]=1;
   manager_property_reply[36]=253;manager_property_reply[40]=248;
   memset(manager_property_reply+44,'a',248);manager_property_reply[44]='/';manager_property_reply[292]=0;manager_property_length=293;}
  manager_property_offset=0;manager_phase=5;return (ssize_t)message->msg_iov[0].iov_len;
 }
 assert(manager_phase==3);
 if(manager_case==84){const unsigned char *b=message->msg_iov[0].iov_base;
  assert(message->msg_iov[0].iov_len==140&&b[8]==0&&b[9]==2&&!b[10]&&!b[11]);return (ssize_t)message->msg_iov[0].iov_len-1;}
 if(manager_case==85){const unsigned char *b=message->msg_iov[0].iov_base;
  assert(message->msg_iov[0].iov_len==140&&!memcmp(b,fixture_lookup_request,8)&&b[8]==0&&b[9]==2&&!b[10]&&!b[11]&&
      !memcmp(b+12,fixture_lookup_request+12,sizeof(fixture_lookup_request)-12)&&b[136]==99&&!b[137]&&!b[138]&&!b[139]);}
 else fixture_check_lookup(message->msg_iov[0].iov_base,message->msg_iov[0].iov_len,99);
 if(manager_case==26)return (ssize_t)message->msg_iov[0].iov_len-1;
 if(manager_case==41){error_seen=1;errno=EINTR;return -1;}
 fixture_lookup_reply(manager_reply,manager_case==20);
 if(manager_case==85){manager_reply[20]=0;manager_reply[21]=2;}
 if(manager_case==21)manager_reply[144]^=1;
 if(manager_case==22)manager_reply[20]=2;
 if(manager_case==23)manager_reply[2]=0;
 if(manager_case==27)manager_reply[0]='B';
 if(manager_case==28)manager_reply[1]=3;
 if(manager_case==29)manager_reply[3]=2;
 if(manager_case==30)manager_reply[4]=255;
 if(manager_case==31)manager_reply[8]=0;
 if(manager_case==32)manager_reply[12]=17;
 if(manager_case==33)manager_reply[17]=2;
 if(manager_case==34)manager_reply[30]=1;
 if(manager_case==35)manager_reply[31]=1;
 if(manager_case==36)manager_reply[32]=108;
 if(manager_case==37)manager_reply[145]=1;
 manager_reply_offset=0;manager_phase=4;return (ssize_t)message->msg_iov[0].iov_len;
}
ssize_t __wrap_recvmsg(int fd,struct msghdr *message,int flags)
{static const char response[]="OK 0123456789abcdef0123456789abcdef\r\n";
 if(manager_phase>=5&&manager_phase<=20){assert(fd==110&&manager_live&&flags==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)&&message->msg_iovlen==1&&
    !message->msg_control&&!message->msg_controllen);
  if(manager_phase==5&&manager_case==58&&!manager_property_eagain++){errno=EAGAIN;return -1;}
  if(manager_phase==5&&manager_case==60)return 0;
  if(manager_phase==6&&manager_case==72&&!manager_id_eagain++){errno=EAGAIN;return -1;}
  if(manager_phase==6&&manager_case==73)return 0;
  if(manager_phase==7&&manager_case==92&&!manager_names_eagain++){errno=EAGAIN;return -1;}
  if(manager_phase==7&&manager_case==93&&manager_property_offset>16)return 0;
  size_t end=manager_property_offset<16?16:manager_property_length;
  assert(message->msg_iov[0].iov_len==end-manager_property_offset);
  size_t n=((manager_phase==5&&manager_case==59)||(manager_phase==6&&manager_case==71)||
            (manager_phase==7&&(manager_case==91||(manager_case==93&&manager_property_offset==16))))?1:end-manager_property_offset;
  memcpy(message->msg_iov[0].iov_base,manager_property_reply+manager_property_offset,n);
  message->msg_flags=((manager_phase==5&&manager_case==61)||(manager_phase==6&&manager_case==74))?MSG_CTRUNC:0;manager_property_offset+=n;
  if(manager_property_offset==manager_property_length){if(manager_phase==5)manager_property_done=1;else if(manager_phase==6)++manager_unit_ids;else if(manager_phase==7)++manager_unit_names;else if(manager_phase==8)++manager_unit_fields;else if(manager_phase==9)++manager_unit_bools;else if(manager_phase==10)++manager_unit_facts;else if(manager_phase==11)++manager_unit_dependencies;else if(manager_phase==12)++manager_unit_timeouts;else if(manager_phase==13)++manager_service_fields;else if(manager_phase==14)++manager_service_scalars;else if(manager_phase==15)++manager_service_empty;else if(manager_phase==16)++manager_service_exec;else if(manager_phase==17)++manager_cgroup_strings;else if(manager_phase==18)++manager_cgroup_scalars;else if(manager_phase==19)++manager_cgroup_arrays;else ++manager_cgroup_ids;}
  return (ssize_t)n;}
 if(manager_phase==4){assert(fd==110&&manager_live&&flags==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)&&message->msg_iovlen==1&&
    !message->msg_control&&!message->msg_controllen);
  if(manager_case==38){errno=EAGAIN;return -1;}
  size_t phase_end=manager_reply_offset<16?16:sizeof(manager_reply);
  assert(message->msg_iov[0].iov_len==phase_end-manager_reply_offset);
  size_t n=manager_case==25?1:phase_end-manager_reply_offset;
  memcpy(message->msg_iov[0].iov_base,manager_reply+manager_reply_offset,n);
  message->msg_flags=manager_case==24?MSG_CTRUNC:0;manager_reply_offset+=n;
  if(manager_reply_offset==sizeof(manager_reply))manager_lookup_done=1;
  return (ssize_t)n;}
 assert(fd==110&&manager_live&&manager_phase==1&&flags==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)&&
        message->msg_iovlen==1&&message->msg_iov[0].iov_len==sizeof(response)-1-(size_t)manager_recv_offset&&!message->msg_control&&!message->msg_controllen);
 if(manager_case==7)return 0;
 if(manager_case==10){errno=EAGAIN;return -1;}
 if(manager_case==43 && !manager_auth_eagain++){errno=EAGAIN;return -1;}
 size_t n=manager_case==11?1:sizeof(response)-1-(size_t)manager_recv_offset;
 memcpy(message->msg_iov[0].iov_base,response+manager_recv_offset,n);
 if(manager_case==8&&!manager_recv_offset)((char *)message->msg_iov[0].iov_base)[3]='G';
 message->msg_flags=manager_case==9?MSG_CTRUNC:0;manager_recv_offset+=(int)n;
 if(manager_recv_offset==(int)sizeof(response)-1)manager_phase=2;
 return (ssize_t)n;}
static int executable_changed_after_bind;
static int opened(int);
static int fake_close(int);
static int __attribute__((used)) fake_project_capture(char p[65],int *root,int executables[3],pid_t *keeper,struct rnr_stage0_project_error *e)
{++project_captures;memset(e,0,sizeof(*e));memset(p,'1',64);p[64]=0;*keeper=0;for(int i=0;i<3;++i)executables[i]=-1;*root=project_bad?-1:opened(0);if(*root<0){e->system_errno=project_bad?EIO:errno;return -1;}for(int i=0;i<3;++i){executables[i]=80+i;executable_live[16+i]=1;}*keeper=99;return 0;}
static int __attribute__((used)) fake_project_check(struct rnr_stage0_project_error *e)
{++project_checks;memset(e,0,sizeof(*e));if(project_bad||(peer_dead_after_bind&&held_binds)){e->system_errno=ESRCH;return -1;}return 0;}
static int __attribute__((used)) fake_project_close(struct rnr_stage0_project_error *e)
{++project_closes;memset(e,0,sizeof(*e));for(int i=0;i<3;++i){assert(executable_live[16+i]);executable_live[16+i]=0;++executable_closes[16+i];}if(fake_close(10)!=0){e->code=RNR_STAGE0_PROJECT_CLEANUP;e->system_errno=errno;e->cleanup_count=1;e->cleanup_errors[0].fd=10;e->cleanup_errors[0].system_errno=errno;return -1;}return 0;}
#define rnr_stage0_capture_project_view(p,r,x,k,e) fake_project_capture(p,r,x,k,e)
#define rnr_stage0_check_project_view(e) fake_project_check(e)
#define rnr_stage0_abandon_project_view(e) fake_project_close(e)

static int bootstrap_calls,bootstrap_bad;
static int __attribute__((used)) fake_bootstrap(struct rnr_stage0_bootstrap_error *e)
{++bootstrap_calls;memset(e,0,sizeof(*e));if(bootstrap_bad){e->code=RNR_STAGE0_BOOTSTRAP_IDENTITY;return -1;}return 0;}
#define rnr_stage0_check_bootstrap(e) fake_bootstrap(e)
#include "../../automation/native/runtime_stage0_records.h"

static int fake_open(const char *,int);
static int fake_openat(int,const char *,int);
static int fake_fstat(int,struct stat *);
static int fake_statx(int,const char *,int,unsigned int,struct statx *);
static int fake_fstatfs(int,struct statfs *);
static ssize_t fake_pread(int,void *,size_t,off_t);
static int fake_close(int);
static int fake_prepare(struct rnr_stage0_launch_error *);
static int fake_check(struct rnr_stage0_launch_error *);
static int fake_bind_cutoff(int64_t,struct rnr_stage0_launch_error *);
static int fake_admit(struct rnr_stage0_admission_error *);
static int fake_held_check(struct rnr_stage0_launch_error *);
static int fake_held_admit(struct rnr_stage0_admission_error *);
static int fake_held_bind(const struct rnr_stage0_installation *,const struct rnr_stage0_task *,const struct rnr_stage0_launch_declaration *,struct rnr_stage0_launch_error *);
static pid_t fake_pid(void);
static long fake_syscall(long,...);
static uid_t fake_uid(void);
static gid_t fake_gid(void);
static int fake_decode_installation(const unsigned char *,size_t,struct rnr_stage0_installation *);
static int fake_decode_task(const unsigned char *,size_t,struct rnr_stage0_task *);
static int fake_decode_declaration(const unsigned char *,size_t,struct rnr_stage0_launch_declaration *);
#define open(p,f) fake_open(p,f)
#define openat(d,p,f,...) fake_openat(d,p,f)
#define fstat(d,s) fake_fstat(d,s)
#define statx(d,p,f,m,s) fake_statx(d,p,f,m,s)
#define fstatfs(d,s) fake_fstatfs(d,s)
#define pread(d,p,n,o) fake_pread(d,p,n,o)
#define close(d) fake_close(d)
#define getpid() fake_pid()
#define geteuid() fake_uid()
#define getegid() fake_gid()
#define syscall(...) fake_syscall(__VA_ARGS__)
#define rnr_stage0_prepare_operational(e) fake_prepare(e)
#define rnr_stage0_check_operational_preparation(e) fake_check(e)
#define rnr_stage0_bind_operational_preparation_cutoff(d,e) fake_bind_cutoff(d,e)
#define rnr_stage0_admit_preparation_fds(e) fake_admit(e)
#include "../../automation/native/runtime_stage0_records.h"
#define rnr_stage0_check_admission_preparation(e) fake_held_check(e)
#define rnr_stage0_admit_held_fds(e) fake_held_admit(e)
#define rnr_stage0_bind_admission_inputs(i,t,d,e) fake_held_bind(i,t,d,e)
#define rnr_stage0_decode_installation(p,n,o) fake_decode_installation(p,n,o)
#define rnr_stage0_decode_task(p,n,o) fake_decode_task(p,n,o)
#define rnr_stage0_decode_launch_declaration(p,n,o) fake_decode_declaration(p,n,o)
#include "test_runtime_stage0_unused_final.h"
#include "../../automation/native/runtime_stage0_preparer.c"
static void fixture_drift_policy(unsigned int role)
{++input_owner.policy.units[role].memory_bytes;}
#undef rnr_stage0_decode_installation
#undef rnr_stage0_decode_task
#undef rnr_stage0_decode_launch_declaration
#undef open
#undef openat
#undef fstat
#undef statx
#undef fstatfs
#undef pread
#undef close
#undef getpid
#undef geteuid
#undef getegid
#undef syscall
#undef rnr_stage0_prepare_operational
#undef rnr_stage0_check_operational_preparation
#undef rnr_stage0_bind_operational_preparation_cutoff
#undef rnr_stage0_admit_preparation_fds

static unsigned char install_raw[448],task_raw[65600],payload[65536];
static unsigned char large_startup_bytes[1048576];
static size_t task_size,payload_size;
static int held_mode,held_checks,held_admits;
static int live[64],closes[64],opens,prepare_calls,admit_calls,clock_calls;
static int writer_fenced,prepare_bad,admit_bad,clock_bad_at,open_bad_at;
static int bad_fd,short_read,extra_eof,read_errno,statx_missing,named_mount_change;
static int named_identity_change,bad_task_size,close_bad,close_bad_fd,reenter_open,reenter_check;
static int foreign,abandon_calls,abandon_saw_closes,bind_calls,bind_bad,missing_policy,tamper_role,short_role,named_bad_role,named_bad_mount_role,extra_eof_role,large_startup,late_read_kind;
enum metadata_fault { DIR_WRITABLE=1, UID_CHANGED, GID_CHANGED, MODE_CHANGED,
    NLINK_CHANGED, SIZE_CHANGED, MTIME_CHANGED, CTIME_CHANGED, DEV_CHANGED,
    INODE_CHANGED, RDEV_CHANGED };
static int metadata_fd,metadata_fault,metadata_after,stat_calls[64];
static int fstat_error_fd,statx_error_fd,statfs_error_fd;
static int late_after_error,close_late;
static int late_decode_stage,reject_decode_stage,decode_calls[3];
static int decode_result(int stage,int result)
{++decode_calls[stage-1];if(late_decode_stage==stage)error_seen=1;return reject_decode_stage==stage?-1:result;}
static int fake_decode_installation(const unsigned char *p,size_t n,struct rnr_stage0_installation *o)
{return decode_result(1,rnr_stage0_decode_installation(p,n,o));}
static int fake_decode_task(const unsigned char *p,size_t n,struct rnr_stage0_task *o)
{return decode_result(2,rnr_stage0_decode_task(p,n,o));}
static int fake_decode_declaration(const unsigned char *p,size_t n,struct rnr_stage0_launch_declaration *o)
{return decode_result(3,rnr_stage0_decode_launch_declaration(p,n,o));}
static void le(unsigned char *p,uint64_t n,int bytes)
{for(int j=0;j<bytes;++j)p[j]=(unsigned char)(n>>(8*j));}
static void reset(void)
{
    memset(mi_live,0,sizeof(mi_live));memset(mi_closed,0,sizeof(mi_closed));mi_seen=mi_fault=mi_late=0;
    memset(cg_live,0,sizeof(cg_live));memset(cg_control_seen,0,sizeof(cg_control_seen));memset(cg_state_seen,0,sizeof(cg_state_seen));
    memset(cg_controller_seen,0,sizeof(cg_controller_seen));cg_controller_case=cg_member_case=0;
    sp_live=sp_role=sp_fault=sp_fault_role=sp_seen=sp_pass[0]=sp_pass[1]=0;
    so_live=so_index=so_case=so_target=so_late=so_phase=so_records=0;so_seen[0]=so_seen[1]=0;
    cg_file_live=cg_control_fault=cg_control_role=cg_control_field=cg_control_postbind=0;
    cg_distinct_policy=cg_file_fault=cg_file_stat_calls=cg_file_closes=cg_state_reverse=0;
    cg_event_role=cg_event_pop_flip=cg_event_freeze_flip=cg_event_late=0;
    cg_scan_seen=cg_scan_phase=cg_scan_fault=cg_scan_late=cg_scan_records=cg_scan_closes=0;
    cg_seen=cg_fault=cg_fault_role=cg_fault_postbind=cg_after_bind=0;
    atomic_store(&preparer_state,PREPARER_NEW);
    atomic_store(&input_owner_pid,0);
    input_owner=(struct preparer_owner){.fds={-1,-1,-1,-1,-1}};
    memset(install_raw,0,128);memcpy(install_raw,"RNRI0001",8);install_raw[8]=1;
    install_raw[16]=1;install_raw[48]=2;install_raw[96]=3;
    le(install_raw+80,129,8);le(install_raw+88,3,8);
    memset(task_raw,0,66);memcpy(task_raw,"RNRT0001",8);task_raw[8]=1;
    task_raw[16]=4;le(task_raw+32,123456789,8);task_raw[40]=2;memcpy(task_raw+64,"{}",2);
    bootstrap_calls=bootstrap_bad=0;project_captures=project_checks=project_closes=project_bad=seen_exec_mask=seen_unit_mask=executable_changed_after_bind=cwd_checks=bad_cwd=manager_auth_done=0;
    held_mode=1;held_checks=held_admits=held_binds=0;
    memcpy(install_raw,"RNRI0002",8);install_raw[8]=2;
    memset(install_raw+128,1,272);memset(install_raw+128,0x11,32);memset(install_raw+400,0,48);
    memcpy(install_raw+200,"11111111-1111-1111-1111-111111111111",36);memset(install_raw+236,0,4);
    memset(install_raw+96,0xff,32);memset(install_raw+336,0x11,32);
    memset(install_raw+16,0x11,32);
    fixture_policy_setup(install_raw);
    memset(task_raw+16,0xaa,16);le(task_raw+40,payload_size,4);
    task_size=64+payload_size;memcpy(task_raw+64,payload,payload_size);
    memset(live,0,sizeof(live));memset(closes,0,sizeof(closes));
    memset(executable_live,0,sizeof(executable_live));memset(executable_closes,0,sizeof(executable_closes));
    memset(unit_live,0,sizeof(unit_live));memset(unit_closes,0,sizeof(unit_closes));
    memset(manager_path_live,0,sizeof(manager_path_live));memset(manager_stat_calls,0,sizeof(manager_stat_calls));
    manager_live=manager_phase=manager_close_count=manager_case=manager_peer_calls=manager_recv_offset=manager_lookup_done=manager_auth_eagain=0;
    manager_drift_role=-1;manager_drift_kind=0;
    manager_reply_offset=0;
    manager_property_offset=manager_property_length=0;manager_property_done=manager_property_eagain=manager_unit_ids=manager_id_eagain=manager_unit_names=manager_names_eagain=manager_unit_fields=manager_unit_bools=manager_unit_facts=manager_unit_dependencies=manager_unit_timeouts=manager_service_fields=manager_service_scalars=manager_service_empty=manager_service_exec=manager_cgroup_strings=manager_cgroup_scalars=manager_cgroup_arrays=manager_cgroup_ids=manager_sends=0;
    memset(unit_stat_calls,0,sizeof(unit_stat_calls));memset(unit_mount_calls,0,sizeof(unit_mount_calls));
    unit_tamper_role=unit_open_role=unit_identity_role=unit_mount_role=unit_named_role=unit_bad_mode_role=unit_eof_role=unit_short_role=-1;
    unit_bad_uid_role=unit_bad_gid_role=unit_negative_size_role=unit_read_error_role=-1;
    unit_change_after_bind=large_unit=unit_late_kind=0;
    opens=prepare_calls=admit_calls=clock_calls=writer_fenced=prepare_bad=admit_bad=0;
    clock_bad_at=open_bad_at=0;bad_fd=-1;
    short_read=extra_eof=read_errno=statx_missing=named_mount_change=0;
    named_identity_change=bad_task_size=close_bad=reenter_open=reenter_check=0;close_bad_fd=-1;
    foreign=abandon_calls=abandon_saw_closes=bind_calls=bind_bad=missing_policy=tamper_role=short_role=named_bad_role=named_bad_mount_role=extra_eof_role=large_startup=late_read_kind=0;
    metadata_fd=fstat_error_fd=statx_error_fd=statfs_error_fd=-1;
    metadata_fault=metadata_after=0;memset(stat_calls,0,sizeof(stat_calls));
    executable_tamper_fd=executable_header_fd=executable_size_fd=executable_mode_fd=-1;
    executable_xattr_fd=executable_read_error_fd=executable_eof_fd=-1;
    executable_identity_fd=executable_mount_fd=executable_late_fd=-1;
    executable_xattr_kind=executable_open_role=large_native=executable_late_kind=peer_dead_after_bind=0;
    memset(executable_stat_calls,0,sizeof(executable_stat_calls));memset(executable_mount_calls,0,sizeof(executable_mount_calls));
    late_after_error=error_seen=close_late=late_decode_stage=reject_decode_stage=0;memset(decode_calls,0,sizeof(decode_calls));
}
static void use_large_startup(void)
{
    large_startup=1;memset(large_startup_bytes,'A',sizeof(large_startup_bytes));
    fixture_number(fixture_policy+1012,sizeof(large_startup_bytes),4);
    fixture_hex(fixture_policy+168,"4e29ad18ab9f42d7c233500771a39d7c852b200baf328fd00fbbe3fecea1eb56");
    fixture_hex(install_raw+304,"4e29ad18ab9f42d7c233500771a39d7c852b200baf328fd00fbbe3fecea1eb56");
    fixture_hex(install_raw+368,"c64894aefb4ec527f074b6352aeb629f56bc345e5a3f7884a8ef0f0b55673af5");
}
static void use_distinct_policy(void)
{
    static const uint64_t cpu[]={900,1500,2000,2000},memory[]={400000000,600000000,700000000,700000000},pids[]={100,140,160,160};
    for(int i=0;i<4;++i){size_t off=1024+128*i;fixture_number(fixture_policy+off+32,cpu[i],8);
        fixture_number(fixture_policy+off+40,memory[i],8);fixture_number(fixture_policy+off+56,pids[i],8);}
    fixture_hex(install_raw+368,"c4f6e0ffa37bfcaeb497249dc67b350ef6bc2fd86818dffc5765437fac8b2f48");cg_distinct_policy=1;
}
static void use_large_native(void)
{
    large_native=1;memset(large_native_bytes,'N',sizeof(large_native_bytes));
    memcpy(large_native_bytes,fixture_native,sizeof(fixture_native));
    fixture_hex(fixture_policy+200,large_native_hash);fixture_number(fixture_policy+980,sizeof(large_native_bytes),8);
    fixture_hex(install_raw+368,"4e1842eec1c36fff4006bca58f3527481614345d19bfbe890fc6cc6102d68e64");
}
static void use_large_unit(void)
{
    large_unit=1;memset(large_unit_bytes,'A',sizeof(large_unit_bytes));
    fixture_hex(fixture_policy+1024,"156c38442089c1323d3e3ba549a6ac24341c47e8b6367bec4740c9b8c865826e");
    fixture_hex(install_raw+368,"bf321e7a002d557616a73bcc86ff8629a1f419c2555e823b943c6b6cb302192e");
}
static int close_total(void)
{int n=manager_close_count;for(int j=0;j<64;++j)n+=closes[j];for(int j=0;j<19;++j)n+=executable_closes[j];for(int j=0;j<10;++j)n+=unit_closes[j];return n;}
static void attempt_abandon(void)
{
    struct rnr_stage0_preparer_error e;
    int before=close_total();++abandon_calls;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1);
    abandon_saw_closes+=close_total()-before;
}
static int opened(int role)
{
    ++opens;
    if(held_mode)assert(bootstrap_calls==1);
    assert(held_mode?(prepare_calls==0 && held_admits==1):(prepare_calls==1 && admit_calls==1));
    if(opens==open_bad_at){error_seen=1;errno=ELOOP;return -1;}
    if(role>=11){int index=role-11;if(executable_live[index])index+=8;
        assert(index<16&&!executable_live[index]);executable_live[index]=1;
        if(opens==reenter_open)attempt_abandon();
        return 64+index;}
    int fd=role+(role>=7?20:10);
    if(live[fd]) fd+=10;
    assert(fd<64 && !live[fd]);live[fd]=1;
    if(opens==reenter_open)attempt_abandon();
    return fd;
}
static int fake_open(const char *path,int flags)
{
    assert(!strcmp(path,"/")||!strcmp(path,"."));
    if(!strcmp(path,"."))++cwd_checks;
    assert(!held_mode||project_captures==1);
    assert(flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    return opened(0);
}
static int fake_openat(int parent,const char *path,int flags)
{
    if((parent==10&&!strcmp(path,"usr"))||(parent>=64&&parent<=71)){
        int role=0;
        if(parent==10)role=11;
        else if(parent==64){assert(!strcmp(path,"lib"));role=12;}
        else if(parent==65){if(!strcmp(path,"rnr"))role=13;else{assert(!strcmp(path,"systemd"));role=17;}}
        else if(parent==66){assert(!strcmp(path,"bootstraps"));role=14;}
        else if(parent==67){assert(!strcmp(path,large_native?large_native_hash:fixture_native_hash));role=15;}
        else if(parent==68){assert(!strcmp(path,"rnr-stage0"));role=16;}
        else if(parent==70){assert(!strcmp(path,"systemd"));role=18;}
        assert(role>=11);int directory=role!=16&&role!=18;
        assert(flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(directory?O_DIRECTORY:O_NONBLOCK)));
        if(role==executable_open_role){error_seen=1;errno=ELOOP;return -1;}
        return opened(role);
    }
    assert(parent>=10 && parent<=16 && live[parent]);
    if(parent==16 && !strcmp(path,"admission-policy.bin") && missing_policy){errno=ENOENT;return -1;}
    int role;
    if(parent==10){assert(strcmp(path,"etc")==0);role=1;}
    else if(parent==11){assert(strcmp(path,"rnr")==0);role=2;}
    else if(parent==12 && held_mode){assert(!strcmp(path,"projects"));role=5;}
    else if(parent==15){assert(!strcmp(path,"1111111111111111111111111111111111111111111111111111111111111111"));role=6;}
    else if(strcmp(path,"installation.bin")==0)role=3;
    else if(strcmp(path,"task.bin")==0)role=4;
    else if(strcmp(path,"admission-policy.bin")==0)role=7;
    else if(strcmp(path,"configuration.json")==0)role=8;
    else if(strcmp(path,"enrollment.json")==0)role=9;
    else{assert(!strcmp(path,"startup-manifest.json"));role=10;}
    int want=O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(role<3||role==5||role==6?O_DIRECTORY:O_NONBLOCK);
    assert(flags==want);
    return opened(role);
}
static int fixture_role(int fd)
{return fd>=37?fd-30:fd>=27?fd-20:fd%10;}
static int fake_fstat(int fd,struct stat *s)
{
    if(fd==740)return sp_stat(s,held_binds);
    if(fd==741)return so_stat(s);
    if(fd>=730&&fd<=731)return mi_stat(fd,s);
    if(fd==720)return cg_file_stat(s);
    if(fd>=700&&fd<716)return cg_stat(fd,s);
    if(fd>=120&&fd<=122){int r=fd-120;assert(manager_path_live[r]);++manager_stat_calls[r];memset(s,0,sizeof(*s));s->st_dev=4;s->st_ino=400+r;
        if(manager_case==14&&r==2&&manager_stat_calls[r]>=2)++s->st_ino;
        s->st_nlink=1;s->st_mode=r==2?S_IFSOCK|0700:S_IFDIR|0755;
        if(r==manager_drift_role&&held_binds&&manager_drift_kind==1)s->st_uid=1;
        if(r==manager_drift_role&&held_binds&&manager_drift_kind==2)s->st_gid=1;
        return 0;}
    if(fd>=90&&fd<100){int index=fd-90,role=index>=6?index-6:index;assert(unit_live[index]);
        ++unit_stat_calls[index];
        memset(s,0,sizeof(*s));s->st_dev=3;s->st_ino=200+role;s->st_nlink=1;
        if((role==unit_identity_role&&unit_stat_calls[index]>=2)||(role==unit_named_role&&index>=6)||
           (role==0&&unit_change_after_bind&&held_binds))++s->st_ino;
        if(role==unit_bad_uid_role)s->st_uid=1;
        if(role==unit_bad_gid_role)s->st_gid=1;
        s->st_mode=role<4?S_IFREG|0644:S_IFDIR|0755;
        if(role==unit_bad_mode_role)s->st_mode|=0020;
        if(role<4)s->st_size=(role==0&&large_unit)?(off_t)sizeof(large_unit_bytes):(off_t)strlen(fixture_units[role]);
        if(role==unit_negative_size_role)s->st_size=-1;
        return 0;}
    if(fd>=64&&fd<=82){assert(executable_live[fd-64]);int role=executable_role(fd);
        ++executable_stat_calls[fd-64];
        memset(s,0,sizeof(*s));s->st_dev=2;s->st_ino=100+role;s->st_nlink=1;
        if(fd==69&&executable_changed_after_bind&&held_binds)++s->st_ino;
        if(fd==executable_identity_fd&&executable_stat_calls[fd-64]>=2)++s->st_ino;
        s->st_mode=(role==16||role==18?S_IFREG:S_IFDIR)|0555;
        if(role==16||role==18)s->st_size=(role==16&&large_native)?sizeof(large_native_bytes):1024;
        if(fd==executable_size_fd)++s->st_size;
        if(fd==executable_mode_fd)s->st_mode|=S_ISUID;
        return 0;}
    assert(fd>=10 && fd<41 && live[fd]);int role=fixture_role(fd);
    ++stat_calls[fd];
    if(fd==fstat_error_fd){error_seen=1;errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=100+role;
    if(fd==20&&bad_cwd&&cwd_checks)++s->st_ino;
    s->st_mode=role<3||role==5||role==6?S_IFDIR|(role==6?0700:0755):S_IFREG|(held_mode?0400:0444);s->st_nlink=1;
    s->st_size=role==3?(held_mode?448:128):role==7?sizeof(fixture_policy):role==8?sizeof(fixture_config)-1:role==9?sizeof(fixture_enrollment)-1:role==10?(large_startup?sizeof(large_startup_bytes):sizeof(fixture_startup)-1):task_size;
    if(fd==bad_fd)s->st_mode=S_IFIFO|0444;
    if(named_identity_change && fd==23)++s->st_ino;
    if(named_bad_role==role && fd>=37)++s->st_ino;
    if(bad_task_size && role==4)s->st_size=65601;
    if(fd==metadata_fd && stat_calls[fd]>=metadata_after){
        switch(metadata_fault){
        case DIR_WRITABLE:s->st_mode|=0020;break;
        case UID_CHANGED:s->st_uid=1;break;
        case GID_CHANGED:s->st_gid=1;break;
        case MODE_CHANGED:s->st_mode=S_IFREG|0555;break;
        case NLINK_CHANGED:s->st_nlink=2;break;
        case SIZE_CHANGED:++s->st_size;break;
        case MTIME_CHANGED:++s->st_mtim.tv_nsec;break;
        case CTIME_CHANGED:++s->st_ctim.tv_nsec;break;
        case DEV_CHANGED:++s->st_dev;break;
        case INODE_CHANGED:++s->st_ino;break;
        case RDEV_CHANGED:++s->st_rdev;break;
        default:assert(0);
        }
    }
    return 0;
}
static int fake_statx(int fd,const char *path,int flags,unsigned int mask,struct statx *s)
{
    if(fd==740){assert(!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return sp_statx(s,held_binds);}
    if(fd==741){assert(!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return so_statx(s);}
    if(fd>=730&&fd<=731){assert(!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return mi_statx(fd,s);}
    if(fd==720){assert(!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return cg_file_statx(s);}
    if(fd>=700&&fd<716){assert(!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return cg_statx(fd,s);}
    if(fd>=120&&fd<=122){int r=fd-120;assert(manager_path_live[r]&&!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);
        memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=4000+r;
        if(r==manager_drift_role&&held_binds&&manager_drift_kind==3)++s->stx_mnt_id;
        return 0;}
    if(fd>=90&&fd<100){int index=fd-90,role=index>=6?index-6:index;
        assert(unit_live[index]&&!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);
        ++unit_mount_calls[index];memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=3000+role;
        if(role==unit_mount_role&&unit_mount_calls[index]>=2)++s->stx_mnt_id;
        return 0;}
    if(fd>=64&&fd<=82){assert(executable_live[fd-64]&&!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);
        ++executable_mount_calls[fd-64];memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=2000+executable_role(fd);
        if(fd==executable_mount_fd&&executable_mount_calls[fd-64]>=2)++s->stx_mnt_id;
        return 0;}
    assert(live[fd] && !strcmp(path,""));
    assert(flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) && mask==STATX_MNT_ID);
    if(fd==statx_error_fd){error_seen=1;errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->stx_mask=statx_missing?0:STATX_MNT_ID;
    s->stx_mnt_id=1000+fixture_role(fd);
    if(named_mount_change && fd==20)++s->stx_mnt_id;
    if(named_bad_mount_role==fixture_role(fd) && fd>=37)++s->stx_mnt_id;
    return 0;
}
static int fake_fstatfs(int fd,struct statfs *s)
{
    if(fd>=730&&fd<=731)return mi_statfs(fd,s);
    if(fd==720)return cg_file_statfs(s);
    if(fd>=700&&fd<716)return cg_statfs(fd,s);
    assert(live[fd]);
    if(fd==statfs_error_fd){error_seen=1;errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->f_type=0xef53;return 0;
}
static ssize_t fake_pread(int fd,void *buf,size_t count,off_t offset)
{
    if(fd==731)return mi_read(buf,count,offset);
    if(fd==720)return cg_file_read(buf,count,offset);
    if(fd>=90&&fd<100){int index=fd-90,role=index>=6?index-6:index;assert(unit_live[index]&&role<4&&offset>=0);
        size_t length=(role==0&&large_unit)?sizeof(large_unit_bytes):strlen(fixture_units[role]);
        const unsigned char *raw=(role==0&&large_unit)?large_unit_bytes:(const unsigned char *)fixture_units[role];
        if((size_t)offset==length){if(role==unit_eof_role){*(char *)buf='x';return 1;}return 0;}
        if(role==unit_read_error_role){error_seen=1;errno=EIO;return -1;}
        if(role==0&&offset>=32768&&unit_late_kind){error_seen=1;if(unit_late_kind==1){errno=EIO;return -1;}}
        assert((size_t)offset+count<=length);memcpy(buf,raw+offset,count);
        if(offset==0&&count==(length>32768?32768:length)){seen_unit_mask|=1<<role;if(unit_tamper_role==role)((unsigned char *)buf)[0]^=1;}
        return (ssize_t)count-(role==unit_short_role?1:0);}
    if(fd>=64&&fd<=82){assert(executable_live[fd-64]&&offset>=0&&count<=32768);int role=executable_role(fd);
        assert(role==16||role==18);size_t length=role==16&&large_native?sizeof(large_native_bytes):1024;
        const unsigned char *raw=role==16?(large_native?large_native_bytes:fixture_native):fixture_manager;
        if((size_t)offset==length){if(fd==executable_eof_fd){*(char *)buf='x';return 1;}return 0;}
        if(fd==executable_late_fd&&offset>=32768&&executable_late_kind){error_seen=1;if(executable_late_kind==1){errno=EIO;return -1;}}
        if(fd==executable_read_error_fd&&count==1024){error_seen=1;errno=EIO;return -1;}
        assert((size_t)offset+count<=length);memcpy(buf,raw+offset,count);
        if(fd==executable_header_fd&&offset==0&&count==64)((unsigned char *)buf)[0]^=1;
        if(fd==executable_tamper_fd&&offset==0&&count==1024)((unsigned char *)buf)[100]^=1;
        if(offset==0&&count==(length>32768?32768:length)){int bit=fd==80?0:fd==81?1:fd==69?2:fd==82?3:fd==71?4:-1;assert(bit>=0);seen_exec_mask|=1<<bit;}
        return (ssize_t)count;}
    assert(live[fd] && count<=32768 && offset>=0);int role=fixture_role(fd);
    assert(role==3||role==4||(role>=7&&role<=10));
    size_t n=role==3?(held_mode?448:128):role==4?task_size:role==7?sizeof(fixture_policy):role==8?sizeof(fixture_config)-1:role==9?sizeof(fixture_enrollment)-1:large_startup?sizeof(large_startup_bytes):sizeof(fixture_startup)-1;
    const unsigned char *raw=role==3?install_raw:role==4?task_raw:role==7?fixture_policy:role==8?fixture_config:role==9?fixture_enrollment:large_startup?large_startup_bytes:fixture_startup;
    if(read_errno){error_seen=1;errno=read_errno;return -1;}
    if(role==10&&offset>=32768&&late_read_kind){error_seen=1;if(late_read_kind==1){errno=EIO;return -1;}}
    if((size_t)offset==n){if(extra_eof||extra_eof_role==role){error_seen=1;*(char *)buf='x';return 1;}return 0;}
    assert((size_t)offset+count<=n);memcpy(buf,raw+offset,count);
    if(tamper_role==role && offset==0 && count)((unsigned char *)buf)[0]^=1;
    if(short_read||short_role==role)error_seen=1;
    return (ssize_t)count-((short_read||short_role==role)?1:0);
}
static int fake_close(int fd)
{
    if(fd==740)return sp_close();
    if(fd==741)return so_close();
    if(fd>=730&&fd<=731)return mi_close(fd);
    if(fd==720)return cg_file_close();
    if(fd>=700&&fd<716)return cg_close(fd);
    if(fd==110){assert(manager_live);manager_live=0;++manager_close_count;
        if(close_late)error_seen=1;
        if(close_bad||fd==close_bad_fd){error_seen=1;errno=EINTR;return -1;}
        return 0;}
    if(fd>=120&&fd<=122){int r=fd-120;assert(manager_path_live[r]);manager_path_live[r]=0;++manager_close_count;
        if(close_late)error_seen=1;
        if(close_bad||fd==close_bad_fd){error_seen=1;errno=EINTR;return -1;}
        return 0;}
    if(fd>=90&&fd<100){int index=fd-90;assert(unit_live[index]);unit_live[index]=0;++unit_closes[index];
        if(close_late)error_seen=1;
        if(close_bad||fd==close_bad_fd){error_seen=1;errno=EINTR;return -1;}
        return 0;}
    if(fd>=64&&fd<=79){assert(executable_live[fd-64]);++executable_closes[fd-64];executable_live[fd-64]=0;
        if(close_late)error_seen=1;
        if(close_bad||fd==close_bad_fd){error_seen=1;errno=EINTR;return -1;}
        return 0;}
    assert(fd>=10 && fd<41 && live[fd]);
    ++closes[fd];live[fd]=0;
    if(close_late)error_seen=1;
    if(close_bad||fd==close_bad_fd){error_seen=1;errno=EINTR;return -1;}return 0;
}
static int fake_prepare(struct rnr_stage0_launch_error *e)
{
    ++prepare_calls;assert(opens==0);memset(e,0,sizeof(*e));
    if(prepare_bad){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}return 0;
}
static int fake_admit(struct rnr_stage0_admission_error *e)
{
    ++admit_calls;assert(prepare_calls==1 && opens==0);memset(e,0,sizeof(*e));
    if(admit_bad){e->code=RNR_STAGE0_ADMISSION_INVENTORY;return -1;}return 0;
}
static int fake_bind_cutoff(int64_t cutoff,struct rnr_stage0_launch_error *e)
{
    assert(cutoff==123456789 && opens==5 && prepare_calls==1 && !bind_calls);
    ++bind_calls;memset(e,0,sizeof(*e));
    if(bind_bad){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}return 0;
}
static int fake_check(struct rnr_stage0_launch_error *e)
{
    if(!e){writer_fenced=1;errno=EINVAL;return -1;}
    ++clock_calls;memset(e,0,sizeof(*e));
    if(clock_calls==reenter_check)attempt_abandon();
    if(writer_fenced || clock_calls==clock_bad_at){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}
    return 0;
}
static pid_t fake_pid(void){return 100;}
static long fake_syscall(long n,...)
{
    if(n==SYS_gettid)return foreign?101:100;
    if(n==SYS_getdents64){va_list a;va_start(a,n);int fd=va_arg(a,int);void *buffer=va_arg(a,void *);
        size_t count=va_arg(a,size_t);va_end(a);if(fd==741)return so_scan(buffer,count,held_binds);return cg_scan(fd,buffer,count);}
    if(n==SYS_name_to_handle_at){va_list a;va_start(a,n);int fd=va_arg(a,int);const char *path=va_arg(a,const char *);
        struct file_handle *h=va_arg(a,struct file_handle *);int *mount=va_arg(a,int *);int flags=va_arg(a,int);va_end(a);
        assert(!strcmp(path,"")&&flags==AT_EMPTY_PATH);return cg_handle(fd,h,mount);}
    assert(n==SYS_openat2);va_list args;va_start(args,n);int parent=va_arg(args,int);
    const char *path=va_arg(args,const char *);const struct open_how *how=va_arg(args,const struct open_how *);
    size_t size=va_arg(args,size_t);va_end(args);assert(size==sizeof(*how));
    if(parent==10&&how->resolve==RESOLVE_IN_ROOT&&how->flags==(unsigned long)(O_RDONLY|O_DIRECTORY|O_CLOEXEC)){
        assert(live[parent]);int result=so_open(path,held_binds);
        if(so_case==13&&so_index==so_target&&(!so_late||held_binds)){error_seen=1;late_after_error=1;}
        return result;
    }
    if(parent==10&&how->resolve==RESOLVE_IN_ROOT){
        assert(live[parent]&&how->flags==(unsigned long)(O_PATH|O_DIRECTORY|O_CLOEXEC));
        int result=sp_open(path,held_binds);
        if(sp_fault>=11&&sp_fault<=13){error_seen=1;late_after_error=1;}
        return result;
    }
    int mi=mi_open(parent,path,10,100);if(mi!=-2){
        assert(how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
        if(mi>=0)assert(how->flags==(unsigned long)(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(mi==730?O_DIRECTORY:O_NONBLOCK)));
        if((mi==730&&mi_fault==26)||(mi==731&&mi_fault==27)){error_seen=1;late_after_error=1;}
        return mi;}
    int cg=cg_open(parent,path,10);if(cg!=-2){
        assert(how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
        if(cg>=0)assert(how->flags==(unsigned long)(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(cg==720?O_NONBLOCK:O_DIRECTORY)));
        if(cg==720&&cg_file_fault==10){error_seen=1;late_after_error=1;}
        if(cg==715&&cg_scan_fault==14&&cg_state_seen[3]==15){error_seen=1;late_after_error=1;}return cg;}
    if(parent==10){int r=!strcmp(path,"run")?0:!strcmp(path,"run/systemd")?1:!strcmp(path,"run/systemd/private")?2:-1;
        assert(live[parent]&&r>=0&&how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
        assert(how->flags==(unsigned long)((r==2?O_PATH:O_RDONLY|O_DIRECTORY)|O_NOFOLLOW|O_CLOEXEC));
        ++opens;if(opens==open_bad_at||(manager_case==13&&r==2)){error_seen=1;errno=ELOOP;return -1;}
        assert(!manager_path_live[r]);manager_path_live[r]=1;
        if(opens==reenter_open)attempt_abandon();
        return 120+r;}
    assert(parent==11&&live[parent]);
    int role=-1;
    if(!strcmp(path,"systemd"))role=4;
    else if(!strcmp(path,"systemd/system"))role=5;
    else{const char *const formats[]={"systemd/system/rnrc%s.service","systemd/system/rnrc%s.slice",
             "systemd/system/rnrw%s.slice","systemd/system/rnrw%s-anchor.slice"};
        for(int i=0;i<4;++i){char expected[128];snprintf(expected,sizeof(expected),formats[i],input_owner.project);if(!strcmp(path,expected))role=i;}}
    assert(role>=0&&how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
    assert(how->flags==(unsigned long)(O_RDONLY|O_CLOEXEC|O_NOFOLLOW|(role>=4?O_DIRECTORY:O_NONBLOCK)));
    ++opens;if(opens==open_bad_at||role==unit_open_role){error_seen=1;errno=ELOOP;return -1;}
    int index=role;if(unit_live[index]){assert(role<4);index=6+role;}
    assert(index<10&&!unit_live[index]);unit_live[index]=1;
    if(opens==reenter_open)attempt_abandon();
    return 90+index;
}
static uid_t fake_uid(void){return 0;}
static gid_t fake_gid(void){return 0;}
static void drained(void)
{for(int fd=0;fd<64;++fd)assert(!live[fd]);for(int i=0;i<19;++i)assert(!executable_live[i]);for(int i=0;i<10;++i)assert(!unit_live[i]);
 assert(!sp_live&&!so_live);
 for(int i=0;i<3;++i)assert(!manager_path_live[i]);
 for(int i=0;i<16;++i)assert(!cg_live[i]);
 assert(!cg_file_live);assert(!mi_live[0]&&!mi_live[1]);
 assert(!manager_live);}

static int fake_held_check(struct rnr_stage0_launch_error *e)
{
    if(!e){writer_fenced=1;return -1;}
    ++held_checks;memset(e,0,sizeof(*e));
    if(held_checks==reenter_check)attempt_abandon();
    if(writer_fenced||held_checks==clock_bad_at||(late_after_error&&error_seen)){
        e->code=RNR_STAGE0_LAUNCH_CLOCK;e->system_errno=ETIMEDOUT;return -1;}
    return 0;
}
static int fake_held_admit(struct rnr_stage0_admission_error *e)
{++held_admits;assert(!opens && !prepare_calls && !admit_calls && held_checks>=2);memset(e,0,sizeof(*e));return admit_bad?-1:0;}
static int fake_held_bind(const struct rnr_stage0_installation *i,const struct rnr_stage0_task *t,
                        const struct rnr_stage0_launch_declaration *d,struct rnr_stage0_launch_error *e)
{
    assert(i==&input_owner.installation && t==&input_owner.task && d->version==3);
    assert(seen_exec_mask==31); /* child, keeper, installed native, PID1 and installed manager */
    assert(seen_unit_mask==15); /* each fixed installed unit before binding */
    assert(cwd_checks>0); /* absolute manager paths resolve in the original root */
    assert(manager_auth_done); /* fixed PID1 peer session before input binding */
    assert(manager_lookup_done); /* original keeper must resolve to the fixed project service */
    assert(manager_property_done); /* actual ordered UnitPath was queried on the same session */
    assert(manager_unit_ids==4); /* all four actual unit IDs were checked */
    assert(manager_unit_names==4); /* aliases must be absent from all four units */
    assert(manager_unit_fields==40); /* fixed state, fragment and action facts */
    assert(manager_unit_bools==28); /* fixed reload, stop and isolation flags */
    assert(manager_unit_facts==8); /* original invocation IDs and empty jobs */
    assert(manager_unit_dependencies==80); /* drop-ins and exact dependencies */
    assert(manager_unit_timeouts==8); /* both job timeouts are infinite */
    assert(manager_service_fields==20); /* fixed service lifecycle and execution strings */
    assert(manager_service_scalars==14); /* keeper, limits, counters and flags */
    assert(manager_service_empty==11); /* no environment or auxiliary commands */
    assert(manager_service_exec==1); /* actual running native command and keeper */
    assert(manager_cgroup_strings==20); /* candidate D cgroup string properties */
    assert(manager_cgroup_scalars==24);
    assert(manager_cgroup_arrays==8);
    assert(manager_cgroup_ids==4);
    assert(mi_seen==3);assert(cg_scan_seen>0);
    assert(cg_seen==255);for(int i=0;i<8;++i)assert(cg_live[i]);
    for(int i=0;i<4;++i)assert(cg_control_seen[i]==63);
    for(int i=0;i<5;++i)assert(cg_state_seen[i]==15U);
    for(int i=0;i<4;++i)assert(cg_controller_seen[i]==3);
    assert(!cg_file_live);
    for(unsigned int role=0;role<4;++role)assert(input_owner.manager_cgroup_ids[role]==UINT64_C(0x1234567800001000)+role);
    for(int role=0;role<4;++role)for(int i=0;i<16;++i)
        assert(input_owner.manager_invocations[role][i]==(i==2?role+1:0));
    assert(d->model.bytes>=input_owner.task_raw+64 && d->model.bytes+d->model.length<=input_owner.task_raw+task_size);
    ++held_binds;cg_after_bind=1;memset(e,0,sizeof(*e));return bind_bad?-1:0;
}
/* Each reset is a new inert unit process model; no real child/files opened. */
int main(void)
{
    static const unsigned char signed_zero[]={0,0,0,0}, signed_minus_one[]={255,255,255,255},
        signed_min[]={0,0,0,128}, signed_max[]={255,255,255,127};
    assert(manager_i32(signed_zero)==0 && manager_i32(signed_minus_one)==-1 &&
           manager_i32(signed_min)==INT32_MIN && manager_i32(signed_max)==INT32_MAX);
    struct rnr_stage0_policy_unit caps={.cpu_millis=1370,.memory_bytes=912345,.swap_bytes=0,.pids=321,.cpu_period_us=100000};
    assert(manager_cgroup_limit(&caps,1)==1370000 && manager_cgroup_limit(&caps,2)==100000 &&
           manager_cgroup_limit(&caps,3)==912345 && manager_cgroup_limit(&caps,4)==0 && manager_cgroup_limit(&caps,5)==321);
    payload_size=fread(payload,1,sizeof(payload),stdin);assert(payload_size>0 && payload_size<65536);
    struct rnr_stage0_preparer_error e,other;
    reset();input_owner.manager_serial=512;manager_case=26;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&manager_sends==0&&!held_binds);drained();
    reset();input_owner.manager_serial=511;manager_case=84;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&manager_sends==1&&!held_binds);drained();
    reset();input_owner.manager_serial=511;manager_case=85;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&manager_sends==1&&
           manager_lookup_done&&manager_peer_calls==4&&!held_binds);drained();
    reset();assert(rnr_stage0_prepare_held_inputs(&e)==0);int checks=held_checks,successful_opens=opens;
    assert(!prepare_calls && !admit_calls && !bind_calls && held_admits==1 && held_binds==1);
    assert(project_captures==1 && project_checks>=2);
    assert(atomic_load(&preparer_state)==PREPARER_ADMISSION_INPUTS_HELD);
    assert(input_owner.task.payload==input_owner.task_raw+64);
    assert(!memcmp(input_owner.task.payload,payload,payload_size));
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    int before=close_total();live[10]=1;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && live[10] && close_total()==before);

    reset();executable_changed_after_bind=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1 && held_binds==1 && e.code==RNR_STAGE0_PREPARER_IDENTITY);drained();
    reset();peer_dead_after_bind=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1&&e.code==RNR_STAGE0_PREPARER_BOOTSTRAP&&e.system_errno==ESRCH);drained();
    reset();bad_cwd=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
    const int manager_failures[]={1,2,4,5,6,7,8,9,12,13,14,21,22,23,24,26,27,28,29,30,31,32,33,34,35,36,37,38,39};
    for(size_t i=0;i<sizeof(manager_failures)/sizeof(*manager_failures);++i){
        reset();manager_case=manager_failures[i];
        enum rnr_stage0_preparer_code code=manager_case==13?RNR_STAGE0_PREPARER_OPEN:
            manager_case==14?RNR_STAGE0_PREPARER_IDENTITY:RNR_STAGE0_PREPARER_PID1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==code&&!held_binds);drained();
    }
    reset();manager_case=10;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    /* Prior operations consume the same budget as authentication and lookup. */
    reset();input_owner.manager_receives=4095;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&manager_auth_done&&manager_reply_offset==0&&!held_binds);drained();
    reset();manager_case=43;input_owner.manager_polls=4095;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!manager_auth_done&&!held_binds);drained();
    for(int scenario=44;scenario<=48;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1);
        assert((scenario==48)==(held_binds==1));drained();
    }
    for(int scenario=49;scenario<=57;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=58;scenario<=65;++scenario){
        reset();manager_case=scenario;
        if(scenario==58||scenario==59||scenario==62){
            assert(rnr_stage0_prepare_held_inputs(&e)==0&&manager_property_done);
            assert(rnr_stage0_abandon_preparation_inputs(&e)==0);
        }else assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);
        drained();
    }
    for(int scenario=66;scenario<=69;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=70;scenario<=78;++scenario){
        reset();manager_case=scenario;
        if(scenario<=72){assert(rnr_stage0_prepare_held_inputs(&e)==0&&manager_unit_ids==4);
            assert(rnr_stage0_abandon_preparation_inputs(&e)==0);}
        else assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);
        drained();
    }
    for(int scenario=79;scenario<=83;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=86;scenario<=93;++scenario){
        reset();manager_case=scenario;
        if(scenario>=90&&scenario<=92){assert(rnr_stage0_prepare_held_inputs(&e)==0&&manager_unit_names==4);
            assert(rnr_stage0_abandon_preparation_inputs(&e)==0);}
        else assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);
        drained();
    }
    for(int scenario=100;scenario<140;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=150;scenario<=182;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=200;scenario<=215;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=230;scenario<310;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=311;scenario<=316;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=330;scenario<=341;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=360;scenario<=384;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=430;scenario<=453;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=470;scenario<=485;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=500;scenario<=519;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=520;scenario<=544;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=550;scenario<=578;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=579;scenario<=582;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=590;scenario<=605;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int scenario=610;scenario<=618;++scenario){
        reset();manager_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&!held_binds);drained();
    }
    for(int fault=1;fault<=10;++fault){
        reset();cg_fault=fault;cg_fault_role=fault==1?5:fault==2?4:fault==3?6:fault==4?7:fault==5?3:4;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    const int cg_late_faults[]={3,4,7,10};
    for(size_t i=0;i<sizeof(cg_late_faults)/sizeof(cg_late_faults[0]);++i){
        reset();cg_fault=cg_late_faults[i];cg_fault_role=cg_fault==3?6:4;cg_fault_postbind=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    }
    for(int field=0;field<6;++field){
        reset();cg_control_fault=1;cg_control_role=4;cg_control_field=field;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    const int cg_control_roles[]={3,6,7};
    for(size_t i=0;i<sizeof(cg_control_roles)/sizeof(cg_control_roles[0]);++i){
        reset();cg_control_fault=1;cg_control_role=cg_control_roles[i];cg_control_field=2;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    for(int fault=2;fault<=4;++fault){
        reset();cg_control_fault=fault;cg_control_role=4;cg_control_field=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    reset();cg_control_fault=1;cg_control_role=6;cg_control_field=3;cg_control_postbind=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    /* A grouped OOM in the keeper leaf must fence, before or after binding. */
    for(int late=0;late<=1;++late){
        reset();cg_control_fault=1;cg_control_role=5;cg_control_field=5;cg_control_postbind=late;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==late);drained();
    }
    reset();use_distinct_policy();assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    const int distinct_roles[]={4,3,6,7},distinct_fields[]={1,2,4};
    for(size_t r=0;r<4;++r)for(size_t f=0;f<3;++f){
        reset();use_distinct_policy();cg_control_fault=1;cg_control_role=distinct_roles[r];cg_control_field=distinct_fields[f];
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    for(int fault=1;fault<=11;++fault){
        reset();cg_file_fault=fault;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);
        assert(cg_file_closes==(fault==1?0:1));
        if(fault==9)assert(e.code==RNR_STAGE0_PREPARER_CLEANUP&&e.cleanup_count==1&&
                           e.cleanup_errors[0].fd==720&&e.cleanup_errors[0].system_errno==EINTR);
        if(fault==10)assert(e.code==RNR_STAGE0_PREPARER_CLOCK&&e.launch.code==RNR_STAGE0_LAUNCH_CLOCK);
        drained();
    }
    for(int fault=1;fault<=10;++fault){
        reset();mi_fault=fault;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    for(int fault=11;fault<=14;++fault){
        reset();mi_fault=fault;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    reset();mi_fault=15;assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    const int mi_bound_failures[]={17,18,19,20,23,24,25,26,27,28};
    for(size_t i=0;i<sizeof(mi_bound_failures)/sizeof(mi_bound_failures[0]);++i){
        reset();mi_fault=mi_bound_failures[i];
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);
        if(mi_fault==24||mi_fault==25){int role=mi_fault==24?0:1;
            assert(mi_closed[role]==1&&e.code==RNR_STAGE0_PREPARER_CLEANUP&&e.cleanup_count==1&&
                   e.cleanup_errors[0].fd==730+role&&e.cleanup_errors[0].system_errno==EINTR);}
        if(mi_fault==26||mi_fault==27){int role=mi_fault==26?0:1;
            assert(mi_closed[role]==1&&e.code==RNR_STAGE0_PREPARER_CLOCK);}
        drained();
    }
    const int mi_bound_successes[]={16,21,22};
    for(size_t i=0;i<sizeof(mi_bound_successes)/sizeof(mi_bound_successes[0]);++i){
        reset();mi_fault=mi_bound_successes[i];assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    }
    reset();mi_fault=2;mi_late=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    const int state_roles[]={4,3,6,7,5};
    for(size_t r=0;r<5;++r)for(int field=6;field<=7;++field){
        reset();cg_control_fault=1;cg_control_role=state_roles[r];cg_control_field=field;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    for(int field=8;field<=9;++field){
        reset();cg_control_fault=1;cg_control_role=7;cg_control_field=field;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    const int empty_membership_roles[]={3,4,6};
    for(size_t r=0;r<3;++r)for(int field=8;field<=9;++field){
        reset();cg_control_fault=1;cg_control_role=empty_membership_roles[r];cg_control_field=field;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    reset();cg_member_case=1;assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int member=2;member<=4;++member){
        reset();cg_member_case=member;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    reset();cg_control_fault=1;cg_control_role=5;cg_control_field=9;cg_control_postbind=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    reset();cg_state_reverse=1;assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int reverse=0;reverse<=1;++reverse){
        reset();cg_event_role=6;cg_event_pop_flip=1;cg_state_reverse=reverse;
        assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    }
    for(size_t r=0;r<5;++r){
        reset();cg_event_role=state_roles[r];cg_event_freeze_flip=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
        if(state_roles[r]!=6){reset();cg_event_role=state_roles[r];cg_event_pop_flip=1;
            assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();}
    }
    reset();cg_event_role=7;cg_event_pop_flip=1;cg_event_late=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    reset();cg_control_fault=1;cg_control_role=7;cg_control_field=7;cg_control_postbind=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    reset();sp_fault=11;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_OPEN&&e.system_errno==EACCES&&e.launch.code==RNR_STAGE0_LAUNCH_CLOCK);drained();
    reset();sp_fault=12;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&e.unadopted_fd==1&&e.launch.code==RNR_STAGE0_LAUNCH_CLOCK);drained();
    reset();sp_fault=13;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_CLOCK&&e.launch.code==RNR_STAGE0_LAUNCH_CLOCK);drained();
    for(int fault=1;fault<=8;++fault){
        reset();cg_scan_fault=fault;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    reset();cg_scan_fault=1;cg_scan_late=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    const int controller_roles[]={2,3,4,6};
    for(size_t r=0;r<4;++r)for(int field=10;field<=11;++field){
        reset();cg_control_fault=1;cg_control_role=controller_roles[r];cg_control_field=field;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    reset();cg_controller_case=1;assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int fault=2;fault<=6;++fault){reset();cg_controller_case=fault;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();}
    const int controller_ok[]={7,10};
    for(size_t i=0;i<sizeof(controller_ok)/sizeof(controller_ok[0]);++i){
        reset();cg_controller_case=controller_ok[i];assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    }
    const int controller_bad[]={8,9,11};
    for(size_t i=0;i<sizeof(controller_bad)/sizeof(controller_bad[0]);++i){
        reset();cg_controller_case=controller_bad[i];
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
    }
    reset();cg_control_fault=1;cg_control_role=6;cg_control_field=11;cg_control_postbind=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    for(int fault=1;fault<=8;++fault){
        reset();sp_fault=fault;assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==(fault==2||fault==3||fault==4||fault==7));drained();
    }
    for(int fault=2;fault<=4;++fault){reset();sp_fault=fault;sp_fault_role=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();}
    reset();sp_fault=9;assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1&&sp_seen==3&&sp_pass[0]==3&&sp_pass[1]==3);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    reset();sp_fault=10;assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds&&e.cleanup_count==1);drained();
    for(int scope=0;scope<14;++scope){reset();so_case=1;so_target=scope;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();}
    reset();so_case=1;so_target=13;so_late=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1);drained();
    for(int scenario=2;scenario<=3;++scenario){reset();so_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1&&so_seen[0]==0x3fff&&so_seen[1]==0x3fff);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();}
    const int overlay_bad[]={4,5,6,7,8,11,12,13};
    for(size_t i=0;i<sizeof(overlay_bad)/sizeof(overlay_bad[0]);++i){reset();so_case=overlay_bad[i];
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();}
    for(int scenario=9;scenario<=10;++scenario){reset();so_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();}
    reset();so_case=14;assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int scenario=15;scenario<=17;++scenario){reset();so_case=scenario;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();}
    const int scan_ok[]={9,11};
    for(size_t i=0;i<sizeof(scan_ok)/sizeof(scan_ok[0]);++i){
        reset();cg_scan_fault=scan_ok[i];assert(rnr_stage0_prepare_held_inputs(&e)==0&&held_binds==1);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    }
    const int scan_bad[]={10,12,13,14};
    for(size_t i=0;i<sizeof(scan_bad)/sizeof(scan_bad[0]);++i){
        reset();cg_scan_fault=scan_bad[i];assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);
        if(cg_scan_fault==13)assert(cg_scan_closes==1&&e.code==RNR_STAGE0_PREPARER_CLEANUP&&e.cleanup_count==1&&
                                    e.cleanup_errors[0].fd==715&&e.cleanup_errors[0].system_errno==EINTR);
        if(cg_scan_fault==14)assert(cg_scan_closes==1&&e.code==RNR_STAGE0_PREPARER_CLOCK);
        drained();
    }
    for(int role=0;role<3;++role)for(int kind=1;kind<=3;++kind){
        reset();manager_drift_role=role;manager_drift_kind=kind;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1&&
               e.code==(kind==3?RNR_STAGE0_PREPARER_IDENTITY:RNR_STAGE0_PREPARER_METADATA));drained();
    }
    for(int scenario=40;scenario<=41;++scenario){
        reset();manager_case=scenario;late_after_error=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_PID1&&
               e.system_errno==(scenario==40?EIO:EINTR)&&e.launch.code==RNR_STAGE0_LAUNCH_CLOCK&&!held_binds);drained();
    }
    for(int scenario=3;scenario<=11;scenario+=8){
        reset();manager_case=scenario;assert(rnr_stage0_prepare_held_inputs(&e)==0&&manager_auth_done);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    }
    for(int scenario=20;scenario<=25;scenario+=5){
        reset();manager_case=scenario;assert(rnr_stage0_prepare_held_inputs(&e)==0&&manager_lookup_done);
        assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    }
    reset();unit_change_after_bind=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1&&held_binds==1&&e.code==RNR_STAGE0_PREPARER_IDENTITY);drained();

    for(int role=0;role<4;++role){
        reset();unit_tamper_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();unit_eof_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_READ&&!held_binds);drained();
        reset();unit_short_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_READ&&!held_binds);drained();
        reset();unit_identity_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();unit_mount_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();unit_named_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();unit_negative_size_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_METADATA&&!held_binds);drained();
        reset();unit_read_error_role=role;late_after_error=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_READ&&e.system_errno==EIO&&
               e.launch.code==RNR_STAGE0_LAUNCH_CLOCK&&!held_binds);drained();
    }
    for(int role=0;role<6;++role){
        reset();unit_open_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_OPEN&&e.system_errno==ELOOP&&!held_binds);drained();
        reset();unit_bad_mode_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_METADATA&&!held_binds);drained();
        reset();unit_bad_uid_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_METADATA&&!held_binds);drained();
        reset();unit_bad_gid_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_METADATA&&!held_binds);drained();
    }
    for(int role=4;role<6;++role){
        reset();unit_identity_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();unit_mount_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
    }
    reset();use_large_unit();assert(rnr_stage0_prepare_held_inputs(&e)==0);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int kind=1;kind<=2;++kind){
        reset();use_large_unit();unit_late_kind=kind;late_after_error=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==(kind==1?RNR_STAGE0_PREPARER_READ:RNR_STAGE0_PREPARER_CLOCK)&&
               e.launch.code==RNR_STAGE0_LAUNCH_CLOCK&&!held_binds);drained();
    }

    const int executable_streams[]={80,81,69,82,71};
    for(size_t i=0;i<sizeof(executable_streams)/sizeof(*executable_streams);++i){
        int fd=executable_streams[i];
        reset();executable_tamper_fd=fd;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();executable_header_fd=fd;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();executable_eof_fd=fd;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_READ&&!held_binds);drained();
        reset();executable_mode_fd=fd;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_METADATA&&!held_binds);drained();
        for(int kind=1;kind<=2;++kind){
            reset();executable_xattr_fd=fd;executable_xattr_kind=kind;
            assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_METADATA&&!held_binds);drained();
        }
        reset();executable_read_error_fd=fd;late_after_error=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_READ&&e.system_errno==EIO&&
               e.launch.code==RNR_STAGE0_LAUNCH_CLOCK&&!held_binds);drained();
        reset();executable_size_fd=fd;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&!held_binds);drained();
        reset();executable_identity_fd=fd;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
        reset();executable_mount_fd=fd;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);drained();
    }
    reset();use_large_native();assert(rnr_stage0_prepare_held_inputs(&e)==0);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    const int native_streams[]={80,81,69};
    for(size_t i=0;i<sizeof(native_streams)/sizeof(*native_streams);++i){
        for(int kind=1;kind<=2;++kind){
            reset();use_large_native();executable_late_fd=native_streams[i];executable_late_kind=kind;late_after_error=1;
            assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==(kind==1?RNR_STAGE0_PREPARER_READ:RNR_STAGE0_PREPARER_CLOCK)&&
                   e.launch.code==RNR_STAGE0_LAUNCH_CLOCK&&!held_binds);drained();
        }
    }
    for(int role=11;role<=18;++role){
        reset();executable_open_role=role;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_OPEN&&e.system_errno==ELOOP&&!held_binds);drained();
    }

    reset();assert(rnr_stage0_prepare_held_inputs(NULL)==-1 && !opens && !prepare_calls);
    assert(rnr_stage0_prepare_inputs(&e)==-1 && !prepare_calls);drained();
    reset();foreign=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !opens && !held_admits);drained();
    reset();admit_bad=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !opens);drained();
    reset();bootstrap_bad=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !opens && !held_binds && bootstrap_calls==1);drained();
    reset();project_bad=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_BOOTSTRAP && e.system_errno==EIO && !project_closes && !held_binds);drained();
    reset();missing_policy=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_OPEN && e.system_errno==ENOENT && !held_binds);drained();
    for(int stage=1;stage<=3;++stage){
        reset();late_after_error=1;late_decode_stage=reject_decode_stage=stage;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_DECODE &&
               e.launch.code==RNR_STAGE0_LAUNCH_CLOCK && e.launch.system_errno==ETIMEDOUT && !held_binds);drained();
        reset();late_after_error=1;late_decode_stage=stage;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_CLOCK &&
               e.launch.system_errno==ETIMEDOUT && !held_binds);drained();
        if(stage==1)assert(decode_calls[1]==0);
    }
    for(int role=7;role<=10;++role){
        reset();tamper_role=role;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_IDENTITY && !held_binds);drained();
        reset();short_role=role;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_READ && !held_binds);drained();
        reset();extra_eof_role=role;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_READ && !held_binds);drained();
        reset();named_bad_role=role;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_IDENTITY && !held_binds);drained();
        reset();named_bad_mount_role=role;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_IDENTITY && !held_binds);drained();
        const int capture_faults[]={UID_CHANGED,GID_CHANGED,MODE_CHANGED,NLINK_CHANGED};
        for(size_t n=0;n<sizeof(capture_faults)/sizeof(*capture_faults);++n){
            reset();metadata_fd=role+20;metadata_fault=capture_faults[n];metadata_after=1;
            assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_METADATA && !held_binds);drained();
        }
        const int changed_faults[]={UID_CHANGED,GID_CHANGED,MODE_CHANGED,NLINK_CHANGED,SIZE_CHANGED,MTIME_CHANGED,CTIME_CHANGED,DEV_CHANGED,INODE_CHANGED,RDEV_CHANGED};
        for(size_t n=0;n<sizeof(changed_faults)/sizeof(*changed_faults);++n){
            reset();metadata_fd=role+20;metadata_fault=changed_faults[n];metadata_after=2;
            assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_IDENTITY && !held_binds);drained();
        }
    }
    reset();fixture_policy[1020]=1;fixture_hex(install_raw+368,"6aab051b9aba165c99e8e7b3c41d9f61cbea213b9a3320a255de5119396d5d19");
    assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_DECODE && !held_binds);drained();
    reset();use_large_startup();
    assert(rnr_stage0_prepare_held_inputs(&e)==0);assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int kind=1;kind<=2;++kind){
        reset();use_large_startup();late_after_error=1;late_read_kind=kind;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==(kind==1?RNR_STAGE0_PREPARER_READ:RNR_STAGE0_PREPARER_CLOCK) &&
               e.launch.code==RNR_STAGE0_LAUNCH_CLOCK && e.launch.system_errno==ETIMEDOUT && !held_binds);drained();
    }
    reset();bind_bad=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && held_binds==1);drained();
    for(int n=1;n<=checks;++n){
        reset();clock_bad_at=n;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
        assert(rnr_stage0_prepare_held_inputs(&other)==-1 && !prepare_calls);drained();
    }
    for(int n=1;n<=successful_opens;++n){
        reset();open_bad_at=n;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
        reset();reenter_open=n;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
        assert(abandon_calls==1 && !abandon_saw_closes);
    }
    reset();reenter_check=checks;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
    assert(abandon_calls==1 && !abandon_saw_closes);
    reset();short_read=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
    reset();read_errno=EINTR;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.system_errno==EINTR);drained();
    reset();extra_eof=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
    reset();named_mount_change=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
    reset();named_identity_change=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1);drained();
    reset();memcpy(install_raw,"RNRI0001",8);install_raw[8]=1;
    assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !held_binds);drained();
    reset();install_raw[236]=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !held_binds);drained();
    reset();task_raw[64]='[';assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !held_binds);drained();
    reset();task_raw[16]^=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_IDENTITY && !held_binds);drained();
    reset();install_raw[96]^=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !held_binds);drained();
    reset();install_raw[336]^=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && !held_binds);drained();
    /* Matching task/install execution pins cannot conceal a different image. */
    for(int byte=0;byte<32;++byte){
        reset();install_raw[16+byte]^=1;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1&&e.code==RNR_STAGE0_PREPARER_IDENTITY&&!held_binds);
        drained();
    }
    reset();close_bad=1;assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.cleanup_count==19);drained();
    reset();assert(rnr_stage0_prepare_held_inputs(&e)==0);close_bad=1;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && e.cleanup_count==23);drained();
    assert(e.project_cleanup.code==RNR_STAGE0_PROJECT_CLEANUP && e.project_cleanup.system_errno==EINTR &&
           e.project_cleanup.cleanup_count==1 && e.project_cleanup.cleanup_errors[0].fd==10 &&
           e.project_cleanup.cleanup_errors[0].system_errno==EINTR);
    before=close_total();assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && close_total()==before);
    reset();assert(rnr_stage0_prepare_held_inputs(&e)==0);close_bad_fd=10;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_CLEANUP &&
           e.system_errno==EINTR && e.cleanup_count==0 && e.project_cleanup.cleanup_count==1 &&
           e.project_cleanup.cleanup_errors[0].fd==10 && e.project_cleanup.cleanup_errors[0].system_errno==EINTR);drained();

    /* A syscall error and simultaneous expiry are separate retained facts.
     * Inject only at the selected syscall, never an earlier close/check. */
    for(int which=0;which<7;++which){
        reset();late_after_error=1;
        enum rnr_stage0_preparer_code primary;
        int failure=EIO;
        if(which==0){open_bad_at=2;primary=RNR_STAGE0_PREPARER_OPEN;failure=ELOOP;}
        else if(which==1){fstat_error_fd=10;primary=RNR_STAGE0_PREPARER_METADATA;}
        else if(which==2){statx_error_fd=10;primary=RNR_STAGE0_PREPARER_METADATA;}
        else if(which==3){statfs_error_fd=10;primary=RNR_STAGE0_PREPARER_METADATA;}
        else if(which==4){read_errno=EIO;primary=RNR_STAGE0_PREPARER_READ;}
        else if(which==5){short_read=1;primary=RNR_STAGE0_PREPARER_READ;failure=0;}
        else {extra_eof=1;primary=RNR_STAGE0_PREPARER_READ;failure=0;}
        assert(rnr_stage0_prepare_held_inputs(&e)==-1 && e.code==primary && e.system_errno==failure);
        assert(e.launch.code==RNR_STAGE0_LAUNCH_CLOCK && e.launch.system_errno==ETIMEDOUT);
        assert(!held_binds);drained();
    }
    /* Named-recheck temporary close failure/late success still gets its required
     * post-call observation, then the already-owned five inputs drain once. */
    for(int fail=0;fail<2;++fail){
        reset();late_after_error=1;close_late=1;close_bad=fail;
        assert(rnr_stage0_prepare_held_inputs(&e)==-1);
        assert(e.code==(fail?RNR_STAGE0_PREPARER_CLEANUP:RNR_STAGE0_PREPARER_CLOCK));
        assert(e.system_errno==(fail?EINTR:ETIMEDOUT));
        assert(e.launch.code==RNR_STAGE0_LAUNCH_CLOCK && e.launch.system_errno==ETIMEDOUT);
        assert(e.cleanup_count==(fail?19U:0U));drained();
    }

    /* Ordinary stages and cross-mode calls fence, never admit effects or recapture. */
    reset();assert(rnr_stage0_prepare_held_inputs(&e)==0);
    assert(rnr_stage0_prepare_inputs(&other)==-1 && !prepare_calls);
    assert(rnr_stage0_abandon_preparation_inputs(&other)==0);drained();
    reset();assert(rnr_stage0_prepare_held_inputs(&e)==0);
    assert(rnr_stage0_prepare_host_view(&other)==-1 && opens==successful_opens);
    assert(rnr_stage0_abandon_preparation_inputs(&other)==0);drained();
    reset();assert(rnr_stage0_prepare_held_inputs(&e)==0);
    assert(rnr_stage0_finish_prepared_operational(&other)==-1 && opens==successful_opens);
    assert(rnr_stage0_abandon_preparation_inputs(&other)==0);drained();

    /* Same fixed reader still accepts legacy128 and preserves its original path. */
    reset();held_mode=0;memcpy(install_raw,"RNRI0001",8);install_raw[8]=1;
    memset(task_raw+16,0,16);task_raw[16]=4;le(task_raw+40,2,4);memcpy(task_raw+64,"{}",2);task_size=66;
    assert(rnr_stage0_prepare_inputs(&e)==0 && prepare_calls==1 && admit_calls==1 && bind_calls==1);
    assert(!held_checks && !held_admits && !held_binds && input_owner.installation.version==1);
    assert(rnr_stage0_prepare_held_inputs(&other)==-1 && !held_admits && !held_checks);
    assert(rnr_stage0_abandon_preparation_inputs(&other)==0);drained();
    puts("held-input mocked checks passed");return 0;
}
