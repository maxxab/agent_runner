/* stdin contains inert fixture DATA only, never a protected task or entry. */
#ifdef NDEBUG
#error "Declaration fixtures require active assertions"
#endif
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "../../automation/native/runtime_stage0_records.h"
static int zero(const void *p,size_t n)
{const unsigned char *b=p;for(size_t i=0;i<n;++i)if(b[i])return 0;return 1;}
int main(void)
{
    unsigned char raw[65537];size_t size=fread(raw,1,sizeof(raw),stdin);
    assert(!ferror(stdin));
    struct rnr_stage0_launch_declaration value;memset(&value,0xff,sizeof(value));
    int result=rnr_stage0_decode_launch_declaration(raw,size,&value);
    if(result){assert(result==-1 && zero(&value,sizeof(value)));puts("{\"accepted\":false}");return 0;}
    assert(value.version==3 && value.unit_path_count>=1 && value.unit_path_count<=32);
    const struct rnr_stage0_text_view views[]={value.model,value.effort,value.run_id,value.supervisor_epoch};
    for(size_t i=0;i<sizeof(views)/sizeof(views[0]);++i){
        assert(views[i].bytes>=raw && views[i].length>0 && views[i].bytes+views[i].length<=raw+size);
    }
    for(size_t i=0;i<value.unit_path_count;++i)
        assert(value.unit_paths[i].bytes>=raw && value.unit_paths[i].bytes+value.unit_paths[i].length<=raw+size);
    /* Fail-clear and full/partial overlap apply to the enlarged output. */
    union {struct rnr_stage0_launch_declaration aligned;unsigned char bytes[70000];} alias;
    memcpy(alias.bytes,raw,size);
    assert(rnr_stage0_decode_launch_declaration(alias.bytes,size,&alias.aligned)==-1);
    assert(zero(&alias.aligned,sizeof(alias.aligned)));
    memcpy(alias.bytes+8,raw,size);
    assert(rnr_stage0_decode_launch_declaration(alias.bytes+8,size,&alias.aligned)==-1);
    assert(zero(&alias.aligned,sizeof(alias.aligned)));
    assert(rnr_stage0_decode_launch_declaration(NULL,size,&alias.aligned)==-1 && zero(&alias.aligned,sizeof(alias.aligned)));
    assert(rnr_stage0_decode_launch_declaration(raw,size,NULL)==-1);
    printf("{\"accepted\":true,\"version\":%u,\"positive_wall_ns\":%" PRId64 ",\"run_capacity\":%" PRIu64 ",\"paths\":%zu,\"model\":\"%.*s\"}\n",
        value.version,value.positive_wall_ns,value.run_capacity,value.unit_path_count,(int)value.model.length,value.model.bytes);
    return 0;
}
