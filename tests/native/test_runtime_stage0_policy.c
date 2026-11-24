/* DATA only; no protected file, clock, effect or native entry. */
#ifdef NDEBUG
#error "Policy fixture requires active assertions"
#endif
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../../automation/native/runtime_stage0_records.h"
static unsigned char raw[9729];
static struct rnr_stage0_policy value;
static void number(unsigned char *p,uint64_t n,size_t bytes)
{for(size_t i=0;i<bytes;++i)p[i]=(unsigned char)(n>>(8*i));}
static int zero(const void *p,size_t bytes)
{const unsigned char *b=p;for(size_t i=0;i<bytes;++i)if(b[i])return 0;return 1;}
static void text(size_t length_offset,size_t data_offset,size_t capacity,const char *s)
{size_t n=strlen(s);assert(n<=capacity);memset(raw+data_offset,0,capacity);number(raw+length_offset,n,4);memcpy(raw+data_offset,s,n);}
static void path(size_t index,const char *s)
{text(1536+256*index,1544+256*index,248,s);}
static void valid(void)
{
 memset(raw,0,sizeof(raw));memcpy(raw,"RNRPOL01",8);number(raw+8,1,4);number(raw+12,9728,4);
 memset(raw+16,1,32);memset(raw+48,2,16);memcpy(raw+64,"11111111-1111-1111-1111-111111111111",36);number(raw+100,1,4);
 for(size_t off=104;off<=392;off+=32)memset(raw+off,(int)(off/32),32);
 number(raw+424,20,4);memset(raw+428,9,20);
 text(460,464,256,"Owner/project-name");text(720,724,256,"Host_With.Exact-Case");
 for(size_t off=980;off<=996;off+=8)number(raw+off,1024,8);
 for(size_t off=1004;off<=1012;off+=4)number(raw+off,128,4);
 number(raw+1016,2,4);
 for(size_t u=0;u<4;++u){size_t off=1024+128*u;memset(raw+off,(int)u+1,32);
  number(raw+off+32,1000,8);number(raw+off+40,1048576,8);number(raw+off+56,64,8);number(raw+off+64,100000,8);}
 path(0,"/run/systemd/transient");path(1,"/etc/systemd/system");
}
static void rejected(size_t bytes)
{memset(&value,0xff,sizeof(value));assert(rnr_stage0_decode_policy(raw,bytes,&value)==-1);assert(zero(&value,sizeof(value)));}
int main(void)
{
 valid();assert(rnr_stage0_decode_policy(raw,9728,&value)==0);
 assert(value.version==1&&value.flags==1&&value.project_id[31]==1&&value.store_instance[15]==2);
 assert(!strcmp(value.boot_id,"11111111-1111-1111-1111-111111111111"));
 assert(value.configuration_digest[0]==3&&value.enrollment_digest[0]==4&&value.startup_digest[0]==5);
 assert(value.native_digest[0]==6&&value.manager_digest[0]==7&&value.python_digest[0]==8);
 assert(value.execution_root[0]==9&&value.asset_root[0]==10&&value.tool_digest[0]==11&&value.daemon_digest[0]==12);
 assert(value.revision_bytes==20&&value.revision[19]==9&&value.revision[20]==0);
 assert(value.repository.bytes==raw+464&&value.repository.length==18);
 assert(value.host.bytes==raw+724&&value.host.length==20);
 assert(value.native_bytes==1024&&value.manager_bytes==1024&&value.python_bytes==1024);
 assert(value.configuration_bytes==128&&value.enrollment_bytes==128&&value.startup_bytes==128);
 assert(value.unit_path_count==2&&value.unit_paths[0].bytes==raw+1544&&value.unit_paths[0].length==22);
 for(size_t u=0;u<4;++u){assert(value.units[u].fragment_digest[0]==u+1);assert(value.units[u].cpu_millis==1000&&value.units[u].memory_bytes==1048576&&value.units[u].pids==64&&value.units[u].swap_bytes==0&&value.units[u].cpu_period_us==100000);}
 /* Every prefix and extra byte rejects; unaligned input is still byte-decoded. */
 for(size_t n=0;n<9728;++n){rejected(n);}
 rejected(9729);
 unsigned char unaligned[9729];memcpy(unaligned+1,raw,9728);assert(rnr_stage0_decode_policy(unaligned+1,9728,&value)==0);
 for(size_t i=0;i<16;++i){valid();raw[i]^=0x80;rejected(9728);}
 const size_t starts[]={16,48,104,136,168,200,232,264,296,328,360,392,428,1024,1152,1280,1408};
 const size_t sizes[]={32,16,32,32,32,32,32,32,32,32,32,32,20,32,32,32,32};
 for(size_t i=0;i<sizeof(starts)/sizeof(*starts);++i){valid();memset(raw+starts[i],0,sizes[i]);rejected(9728);valid();memset(raw+starts[i],0,sizes[i]);raw[starts[i]+sizes[i]-1]=1;assert(rnr_stage0_decode_policy(raw,9728,&value)==0);}
 for(size_t i=448;i<460;++i){valid();raw[i]=1;rejected(9728);}
 valid();number(raw+424,32,4);memset(raw+428,7,32);assert(rnr_stage0_decode_policy(raw,9728,&value)==0&&value.revision_bytes==32);
 const unsigned invalid_oid[]={0,19,21,31,33,0xffffffffU};for(size_t i=0;i<6;++i){valid();number(raw+424,invalid_oid[i],4);rejected(9728);}
 for(size_t i=1020;i<1024;++i){valid();raw[i]=1;rejected(9728);}
 for(size_t u=0;u<4;++u)for(size_t i=72;i<128;++i){valid();raw[1024+128*u+i]=1;rejected(9728);}
 for(size_t slot=0;slot<32;++slot)for(size_t i=slot<2?4:0;i<256;++i){
  if(slot<2&&i>=8&&i<8+strlen(slot==0?"/run/systemd/transient":"/etc/systemd/system"))continue;
  valid();raw[1536+256*slot+i]=1;rejected(9728);
 }
 for(size_t i=464+18;i<720;++i){valid();raw[i]=1;rejected(9728);}
 for(size_t i=724+20;i<980;++i){valid();raw[i]=1;rejected(9728);}
 const char *repos[]={"owner","/repo","owner/","a/b/c","./b","a/..","a/b c","a/b\\c"};
 for(size_t i=0;i<8;++i){valid();text(460,464,256,repos[i]);rejected(9728);}
 valid();number(raw+460,0,4);rejected(9728);valid();number(raw+460,257,4);rejected(9728);
 valid();number(raw+720,0,4);rejected(9728);valid();number(raw+720,257,4);rejected(9728);
 valid();text(720,724,256," \t\r\n\v\f");rejected(9728);
 for(unsigned int c=0;c<256;++c){valid();raw[724]=(unsigned char)c;if(c==0||c>127)rejected(9728);else assert(rnr_stage0_decode_policy(raw,9728,&value)==0);}
 valid();text(720,724,256," Case Preserved ");assert(rnr_stage0_decode_policy(raw,9728,&value)==0);
 const size_t elf_offsets[]={980,988,996};
 for(size_t i=0;i<3;++i){valid();number(raw+elf_offsets[i],0,8);rejected(9728);valid();number(raw+elf_offsets[i],33554432,8);assert(rnr_stage0_decode_policy(raw,9728,&value)==0);number(raw+elf_offsets[i],33554433,8);rejected(9728);}
 const size_t file_offsets[]={1004,1008,1012};const uint64_t maxima[]={131072,131072,1048576};
 for(size_t i=0;i<3;++i){valid();number(raw+file_offsets[i],0,4);rejected(9728);valid();number(raw+file_offsets[i],maxima[i],4);assert(rnr_stage0_decode_policy(raw,9728,&value)==0);number(raw+file_offsets[i],maxima[i]+1,4);rejected(9728);}
 for(size_t u=0;u<4;++u){size_t off=1024+128*u;
  const size_t positive[]={32,40,56};for(size_t i=0;i<3;++i){valid();number(raw+off+positive[i],0,8);rejected(9728);valid();number(raw+off+positive[i],UINT64_MAX,8);rejected(9728);}
  valid();number(raw+off+32,1001,8);rejected(9728);valid();number(raw+off+48,1,8);rejected(9728);
  valid();number(raw+off+64,99999,8);rejected(9728);
 }
 const size_t cap_offsets[]={32,40,56};
 for(size_t k=0;k<3;++k){valid();number(raw+1024+cap_offsets[k],cap_offsets[k]==32?1010:2097152,8);rejected(9728);
  valid();number(raw+1408+cap_offsets[k],cap_offsets[k]==32?1010:2097152,8);rejected(9728);}
 uint64_t max_cpu=((uint64_t)INT64_MAX/1000)/10*10;
 valid();for(size_t u=0;u<4;++u){number(raw+1024+128*u+32,max_cpu,8);number(raw+1024+128*u+40,INT64_MAX,8);number(raw+1024+128*u+56,INT64_MAX,8);}assert(rnr_stage0_decode_policy(raw,9728,&value)==0);
 for(size_t u=0;u<4;++u){number(raw+1024+128*u+32,max_cpu+10,8);}
 rejected(9728);
 const char *bad_paths[]={"/", "relative", "/a/", "/a//b", "/a/./b", "/a/../b", "/a b", "/a\\b", "/a:b", "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"};
 for(size_t i=0;i<10;++i){valid();path(1,bad_paths[i]);rejected(9728);}
 valid();path(1,"/run/systemd/transient");rejected(9728);valid();path(0,"/other");rejected(9728);
 valid();number(raw+1016,0,4);rejected(9728);valid();number(raw+1016,33,4);rejected(9728);
 valid();number(raw+1536+256,249,4);rejected(9728);
 valid();number(raw+1016,32,4);
 for(size_t i=1;i<32;++i){char s[]="/uAA";s[2]=(char)('A'+i/26);s[3]=(char)('A'+i%26);path(i,s);}
 assert(rnr_stage0_decode_policy(raw,9728,&value)==0&&value.unit_path_count==32);
 valid();char longest[249];longest[0]='/';memset(longest+1,'a',247);longest[248]=0;path(1,longest);
 assert(rnr_stage0_decode_policy(raw,9728,&value)==0&&value.unit_paths[1].length==248);
 valid();char repository[257];memset(repository,'a',256);repository[127]='/';repository[256]=0;text(460,464,256,repository);
 char host[257];memset(host,'H',256);host[256]=0;text(720,724,256,host);
 assert(rnr_stage0_decode_policy(raw,9728,&value)==0&&value.repository.length==256&&value.host.length==256);
 valid();raw[64]='A';rejected(9728);valid();memcpy(raw+64,"00000000-0000-0000-0000-000000000000",36);rejected(9728);
 valid();number(raw+100,0,4);rejected(9728);valid();number(raw+100,3,4);rejected(9728);
 memset(&value,0xff,sizeof(value));assert(rnr_stage0_decode_policy(NULL,9728,&value)==-1&&zero(&value,sizeof(value)));
 valid();assert(rnr_stage0_decode_policy(raw,9728,NULL)==-1);
 union{struct rnr_stage0_policy align;unsigned char bytes[16384];} alias;
 valid();memcpy(alias.bytes,raw,9728);assert(rnr_stage0_decode_policy(alias.bytes,9728,&alias.align)==-1&&zero(&alias.align,sizeof(alias.align)));
 memcpy(alias.bytes+8,raw,9728);assert(rnr_stage0_decode_policy(alias.bytes+8,9728,&alias.align)==-1&&zero(&alias.align,sizeof(alias.align)));
 memcpy(alias.bytes,raw,9728);struct rnr_stage0_policy *tail=(void *)(alias.bytes+8);assert(rnr_stage0_decode_policy(alias.bytes,9728,tail)==-1&&zero(tail,sizeof(*tail)));
 return 0;
}
