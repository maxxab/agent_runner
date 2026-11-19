/* Inert record decoder fixtures. No filesystem, native entry or host effects. */
#ifdef NDEBUG
#error "Record fixtures require active assertions"
#endif
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../../automation/native/runtime_stage0_records.h"

static void u64(unsigned char *p, uint64_t n)
{
    for (unsigned int i = 0; i < 8; ++i) p[i] = (unsigned char)(n >> (8*i));
}
static int zero(const void *p, size_t n)
{
    const unsigned char *b = p;
    for (size_t i = 0; i < n; ++i) if (b[i]) return 0;
    return 1;
}
static void installation(unsigned char *b)
{
    memset(b, 0, 128); memcpy(b, "RNRI0001", 8); b[8] = 1;
    b[16] = 0xa1; b[48] = 0xb2; u64(b+80, 129); u64(b+88, 3); b[96] = 0xc3;
}
static void task(unsigned char *b)
{
    memset(b, 0, 67); memcpy(b, "RNRT0001", 8); b[8] = 1;
    b[16] = 0xa4; u64(b+32, 0x0102030405060708ULL); b[40] = 3;
    memcpy(b+64, "abc", 3); /* Native record is opaque; Python validates JSON. */
}
static void output(unsigned char *b)
{
    memset(b, 0, 128); memcpy(b, "RNRP0001", 8); b[8] = 1;
    b[16] = 0xd5; b[32] = 0xe6; b[64] = 0xf7; u64(b+96, 1024); u64(b+104, 9);
}
int main(void)
{
    unsigned char b[65601], copy[128];
    struct rnr_stage0_installation i;
    struct rnr_stage0_task t;
    struct rnr_stage0_output o;
    installation(b);
    assert(rnr_stage0_decode_installation(b,128,&i)==0);
    assert(i.runtime.data_blocks==129 && i.runtime.hash_blocks==3);
    assert(i.runtime.root[0]==0xa1 && i.runtime.salt[0]==0xb2 && i.asset_root[0]==0xc3);
    const uint64_t geometry[][2]={{2,1},{128,1},{129,3},{1024,9},{131072,1033}};
    for (size_t n=0;n<sizeof(geometry)/sizeof(geometry[0]);++n) {
        installation(b);u64(b+80,geometry[n][0]);u64(b+88,geometry[n][1]);
        assert(rnr_stage0_decode_installation(b,128,&i)==0);
        u64(b+88,geometry[n][1]+1);
        memset(&i,0xff,sizeof(i));
        assert(rnr_stage0_decode_installation(b,128,&i)==-1 && zero(&i,sizeof(i)));
    }
    const size_t install_bad[]={0,8,9,12,16,48,96};
    for (size_t n=0;n<sizeof(install_bad)/sizeof(install_bad[0]);++n) {
        installation(b); b[install_bad[n]] ^= b[install_bad[n]] ? b[install_bad[n]] : 2;
        memset(&i,0xff,sizeof(i));
        assert(rnr_stage0_decode_installation(b,128,&i)==-1 && zero(&i,sizeof(i)));
    }
    const uint64_t bad_blocks[]={0,1,131073,UINT64_MAX};
    for (size_t n=0;n<sizeof(bad_blocks)/sizeof(bad_blocks[0]);++n) {
        installation(b);u64(b+80,bad_blocks[n]);
        assert(rnr_stage0_decode_installation(b,128,&i)==-1 && zero(&i,sizeof(i)));
    }
    installation(b);memcpy(copy,b,128);
    assert(rnr_stage0_decode_installation(b,127,&i)==-1 && zero(&i,sizeof(i)));
    assert(rnr_stage0_decode_installation(b,129,&i)==-1 && zero(&i,sizeof(i)));
    assert(rnr_stage0_decode_installation(NULL,128,&i)==-1 && zero(&i,sizeof(i)));
    assert(rnr_stage0_decode_installation(b,128,NULL)==-1);
    assert(memcmp(b,copy,128)==0);

    task(b);
    assert(rnr_stage0_decode_task(b,67,&t)==0);
    assert(t.wall_cutoff_ns==0x0102030405060708LL && t.task_id[0]==0xa4);
    assert(t.payload==b+64 && t.payload_bytes==3 && memcmp(t.payload,"abc",3)==0);
    const size_t task_bad[]={0,8,12,16,44,63};
    for (size_t n=0;n<sizeof(task_bad)/sizeof(task_bad[0]);++n) {
        task(b);b[task_bad[n]] ^= b[task_bad[n]] ? b[task_bad[n]] : 2;
        memset(&t,0xff,sizeof(t));
        assert(rnr_stage0_decode_task(b,67,&t)==-1 && zero(&t,sizeof(t)));
    }
    task(b);u64(b+32,0);
    assert(rnr_stage0_decode_task(b,67,&t)==-1 && zero(&t,sizeof(t)));
    task(b);u64(b+32,UINT64_MAX);
    assert(rnr_stage0_decode_task(b,67,&t)==-1 && zero(&t,sizeof(t)));
    task(b);
    assert(rnr_stage0_decode_task(b,66,&t)==-1 && zero(&t,sizeof(t)));
    assert(rnr_stage0_decode_task(b,68,&t)==-1 && zero(&t,sizeof(t)));
    assert(rnr_stage0_decode_task(NULL,67,&t)==-1 && zero(&t,sizeof(t)));
    assert(rnr_stage0_decode_task(b,67,NULL)==-1);
    task(b);memset(b+40,0,4);
    assert(rnr_stage0_decode_task(b,64,&t)==-1 && zero(&t,sizeof(t)));
    task(b);memset(b+64,'x',65537);memset(b+40,0,4);b[42]=1;
    assert(rnr_stage0_decode_task(b,65600,&t)==0 && t.payload_bytes==65536);
    b[40]=1;
    assert(rnr_stage0_decode_task(b,65601,&t)==-1 && zero(&t,sizeof(t)));

    output(b);
    assert(rnr_stage0_decode_output(b,128,&o)==0);
    assert(o.task_id[0]==0xd5 && o.launch.root[0]==0xe6 && o.launch.salt[0]==0xf7);
    assert(o.launch.data_blocks==1024 && o.launch.hash_blocks==9);
    const size_t output_bad[]={0,8,12,16,32,64,112,127};
    for (size_t n=0;n<sizeof(output_bad)/sizeof(output_bad[0]);++n) {
        output(b);b[output_bad[n]] ^= b[output_bad[n]] ? b[output_bad[n]] : 2;
        memset(&o,0xff,sizeof(o));
        assert(rnr_stage0_decode_output(b,128,&o)==-1 && zero(&o,sizeof(o)));
    }
    output(b);u64(b+96,1025);
    assert(rnr_stage0_decode_output(b,128,&o)==-1 && zero(&o,sizeof(o)));
    output(b);u64(b+104,8);
    assert(rnr_stage0_decode_output(b,128,&o)==-1 && zero(&o,sizeof(o)));
    output(b);
    assert(rnr_stage0_decode_output(b,127,&o)==-1 && zero(&o,sizeof(o)));
    assert(rnr_stage0_decode_output(b,129,&o)==-1 && zero(&o,sizeof(o)));
    assert(rnr_stage0_decode_output(NULL,128,&o)==-1 && zero(&o,sizeof(o)));
    assert(rnr_stage0_decode_output(b,128,NULL)==-1);
    return 0;
}
