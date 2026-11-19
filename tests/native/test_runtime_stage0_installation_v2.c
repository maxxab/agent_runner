/* Data only: no file/clock/Store/resource/native-entry operations. */
#ifdef NDEBUG
#error "Record fixtures require active assertions"
#endif
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../../automation/native/runtime_stage0_records.h"

static void u64(unsigned char *p, uint64_t n)
{ for (unsigned int i=0;i<8;++i)p[i]=(unsigned char)(n>>(8*i)); }
static int zero(const void *p,size_t n)
{
    const unsigned char *b=p;
    for(size_t i=0;i<n;++i)if(b[i])return 0;
    return 1;
}
static void valid(unsigned char *b)
{
    memset(b,0,449);memcpy(b,"RNRI0002",8);b[8]=2;
    b[16]=0xa1;b[48]=0xb2;u64(b+80,129);u64(b+88,3);b[96]=0xc3;
    b[128]=0xd4;b[175]=0xe5;
    u64(b+176,0xfedcba9876543210ULL);u64(b+184,0x0123456789abcdefULL);
    b[192]=0xff;b[195]=0x80;b[196]=0x01;b[199]=0xfe;
    memcpy(b+200,"12345678-9abc-def0-1234-56789abcdef0",36);
    b[240]=1;b[303]=2;b[304]=3;b[367]=4;b[368]=5;
}
static void rejected(unsigned char *b,size_t n)
{
    struct rnr_stage0_installation value;
    memset(&value,0xff,sizeof(value));
    assert(rnr_stage0_decode_installation(b,n,&value)==-1);
    assert(zero(&value,sizeof(value)));
}
int main(void)
{
    unsigned char b[449];struct rnr_stage0_installation value;
    valid(b);memset(&value,0xff,sizeof(value));
    assert(rnr_stage0_decode_installation(b,448,&value)==0);
    assert(value.version==2 && value.runtime.data_blocks==129 && value.runtime.hash_blocks==3);
    assert(value.project_id[0]==0xd4 && value.store_instance[15]==0xe5);
    assert(value.store_device==0xfedcba9876543210ULL && value.store_inode==0x0123456789abcdefULL);
    assert(value.filesystem_id[0]==0x800000ffU && value.filesystem_id[1]==0xfe000001U);
    assert(strcmp(value.boot_id,"12345678-9abc-def0-1234-56789abcdef0")==0);
    assert(value.configuration_digest[0]==1 && value.enrollment_digest[31]==2);
    assert(value.startup_digest[0]==3 && value.execution_root[31]==4 && value.unit_policy_digest[0]==5);
    /* Device and filesystem zero bit-patterns are structural data, not trust. */
    valid(b);memset(b+176,0,8);memset(b+192,0,8);
    assert(rnr_stage0_decode_installation(b,448,&value)==0);
    assert(value.store_device==0 && value.filesystem_id[0]==0 && value.filesystem_id[1]==0);
    /* Reuse v2 output for legacy v1: every extension must clear. */
    valid(b);assert(rnr_stage0_decode_installation(b,448,&value)==0);
    memcpy(b,"RNRI0001",8);b[8]=1;
    assert(rnr_stage0_decode_installation(b,128,&value)==0 && value.version==1);
    struct rnr_stage0_installation legacy={0};
    legacy.version=1;legacy.runtime=value.runtime;memcpy(legacy.asset_root,value.asset_root,32);
    assert(memcmp(&value,&legacy,sizeof(value))==0);
    /* Exact framing: neither legacy bytes nor version can bypass v2 checks. */
    valid(b);rejected(b,447);rejected(b,449);rejected(b,128);
    valid(b);memcpy(b,"RNRI0001",8);b[8]=1;rejected(b,448);
    valid(b);b[8]=1;rejected(b,448);
    valid(b);memcpy(b,"RNRI0001",8);rejected(b,448);
    valid(b);b[0]='X';rejected(b,448);
    const size_t starts[]={16,48,96,128,160,240,272,304,336,368};
    const size_t sizes[]={32,32,32,32,16,32,32,32,32,32};
    for(size_t i=0;i<sizeof(starts)/sizeof(starts[0]);++i){
        valid(b);memset(b+starts[i],0,sizes[i]);rejected(b,448);
        /* A nonzero last byte suffices; no first-byte sentinel convention. */
        valid(b);memset(b+starts[i],0,sizes[i]);b[starts[i]+sizes[i]-1]=1;
        assert(rnr_stage0_decode_installation(b,448,&value)==0);
    }
    valid(b);u64(b+184,0);rejected(b,448);
    for(size_t i=12;i<16;++i){valid(b);b[i]=1;rejected(b,448);}
    for(size_t i=236;i<240;++i){valid(b);b[i]=1;rejected(b,448);}
    for(size_t i=400;i<448;++i){valid(b);b[i]=1;rejected(b,448);}
    const size_t boot_bad[]={200,208,209,213,218,223,235};
    for(size_t i=0;i<sizeof(boot_bad)/sizeof(boot_bad[0]);++i){
        valid(b);b[boot_bad[i]]='X';rejected(b,448);
    }
    valid(b);b[210]='A';rejected(b,448);
    valid(b);memcpy(b+200,"00000000-0000-0000-0000-000000000000",36);rejected(b,448);
    valid(b);u64(b+80,131073);rejected(b,448);
    valid(b);u64(b+88,4);rejected(b,448);
    assert(rnr_stage0_decode_installation(NULL,448,&value)==-1 && zero(&value,sizeof(value)));
    valid(b);assert(rnr_stage0_decode_installation(b,448,NULL)==-1);
    /* Aligned full and partial aliases must reject before reading. The output
     * itself is then fail-cleared, even when that overlaps the raw input. */
    union { struct rnr_stage0_installation align; unsigned char bytes[1024]; } alias;
    valid(alias.bytes);
    assert(rnr_stage0_decode_installation(alias.bytes,448,&alias.align)==-1);
    assert(zero(&alias.align,sizeof(alias.align)));
    valid(alias.bytes+8);
    assert(rnr_stage0_decode_installation(alias.bytes+8,448,&alias.align)==-1);
    assert(zero(&alias.align,sizeof(alias.align)));
    valid(alias.bytes);
    struct rnr_stage0_installation *tail=(void *)(alias.bytes+8);
    assert(rnr_stage0_decode_installation(alias.bytes,448,tail)==-1);
    assert(zero(tail,sizeof(*tail)));
    return 0;
}
