/* Independent fixed D-Bus GetUnitByPID test vectors; never a host client. */
#include <stdio.h>
static const unsigned char fixture_lookup_request[136]={
    0x6c, 0x01, 0x02, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x77, 0x00, 0x00, 0x00, 0x01, 0x01, 0x6f, 0x00, 0x19, 0x00, 0x00, 0x00,
    0x2f, 0x6f, 0x72, 0x67, 0x2f, 0x66, 0x72, 0x65, 0x65, 0x64, 0x65, 0x73,
    0x6b, 0x74, 0x6f, 0x70, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x64,
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x73, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x6f, 0x72, 0x67, 0x2e, 0x66, 0x72, 0x65, 0x65,
    0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x2e, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x64, 0x31, 0x2e, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x73, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x47, 0x65, 0x74, 0x55, 0x6e, 0x69, 0x74, 0x42,
    0x79, 0x50, 0x49, 0x44, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x67, 0x00,
    0x01, 0x75, 0x00, 0x00,
};
static const char fixture_lookup_path[]="/org/freedesktop/systemd1/unit/rnrc"
    "1111111111111111111111111111111111111111111111111111111111111111_2eservice";
/* Hand-checked Properties.Get(Manager, UnitPath), serial 2; no activation. */
static const unsigned char fixture_unit_path_request[]={
    0x6c,0x01,0x02,0x01,0x35,0,0,0,0x02,0,0,0,0x68,0,0,0,
    0x01,0x01,0x6f,0,0x19,0,0,0,'/','o','r','g','/','f','r','e',
    'e','d','e','s','k','t','o','p','/','s','y','s','t','e','m','d',
    '1',0,0,0,0,0,0,0,0x02,0x01,0x73,0,0x1f,0,0,0,
    'o','r','g','.','f','r','e','e','d','e','s','k','t','o','p','.',
    'D','B','u','s','.','P','r','o','p','e','r','t','i','e','s',0,
    0x03,0x01,0x73,0,0x03,0,0,0,'G','e','t',0,0,0,0,0,
    0x08,0x01,0x67,0,0x02,'s','s',0,
    0x20,0,0,0,'o','r','g','.','f','r','e','e','d','e','s','k',
    't','o','p','.','s','y','s','t','e','m','d','1','.','M','a','n',
    'a','g','e','r',0,0,0,0,0x08,0,0,0,'U','n','i','t',
    'P','a','t','h',0
};
static const unsigned char fixture_unit_path_reply[]={
    'l',2,1,1,60,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,2,0,0,0,
    8,1,'g',0,1,'v',0,0,2,'a','s',0,52,0,0,0,22,0,0,0,
    '/','r','u','n','/','s','y','s','t','e','m','d','/','t','r','a',
    'n','s','i','e','n','t',0,0,19,0,0,0,'/','e','t','c','/',
    's','y','s','t','e','m','d','/','s','y','s','t','e','m',0
};
#define FIXTURE_PROJECT "1111111111111111111111111111111111111111111111111111111111111111"
static const char *const fixture_unit_names[]={"rnrc" FIXTURE_PROJECT ".service", "rnrc" FIXTURE_PROJECT ".slice",
    "rnrw" FIXTURE_PROJECT ".slice", "rnrw" FIXTURE_PROJECT "-anchor.slice"};
static const char *const fixture_unit_objects[]={
    "/org/freedesktop/systemd1/unit/rnrc" FIXTURE_PROJECT "_2eservice",
    "/org/freedesktop/systemd1/unit/rnrc" FIXTURE_PROJECT "_2eslice",
    "/org/freedesktop/systemd1/unit/rnrw" FIXTURE_PROJECT "_2eslice",
    "/org/freedesktop/systemd1/unit/rnrw" FIXTURE_PROJECT "_2danchor_2eslice"};
/* Fixed candidate D cgroup string values, constructed independently of the reader. */
static const char *const fixture_cgroup_strings[]={"Slice","ControlGroup","DelegateSubgroup","ManagedOOMSwap","ManagedOOMMemoryPressure"};
static size_t fixture_cgroup_string_reply(unsigned char *out,unsigned int field,unsigned int role)
{
 assert(field<5&&role<4);char value[192];
 if(field==0)snprintf(value,sizeof(value),"%s",role==0?fixture_unit_names[1]:role==3?fixture_unit_names[2]:"-.slice");
 else if(field==1){if(role==0)snprintf(value,sizeof(value),"/%s/%s",fixture_unit_names[1],fixture_unit_names[0]);
  else if(role==3)snprintf(value,sizeof(value),"/%s/%s",fixture_unit_names[2],fixture_unit_names[3]);
  else snprintf(value,sizeof(value),"/%s",fixture_unit_names[role]);}
 else snprintf(value,sizeof(value),"%s",field==2?(role?"":"keeper"):"auto");
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,1,'s',0,0};
 size_t n=strlen(value);memcpy(out,header,sizeof(header));out[4]=(unsigned char)(9+n);out[20]=(unsigned char)(221+field*4+role);
 out[36]=(unsigned char)n;out[37]=out[38]=out[39]=0;memcpy(out+40,value,n+1);return 41+n;
}
static const char *const fixture_cgroup_scalars[]={"Delegate","CPUQuotaPerSecUSec","CPUQuotaPeriodUSec","MemoryMax","MemorySwapMax","TasksMax"};
static size_t fixture_cgroup_scalar_reply(unsigned char *out,unsigned int field,unsigned int role,int distinct)
{
 assert(field<6&&role<4);uint64_t value=field==0?(role==0):field==1?1000000:field==2?100000:
     field==3?536870912:field==4?0:128;
 if(distinct){static const uint64_t cpu[]={900,1500,2000,2000},memory[]={400000000,600000000,700000000,700000000},pids[]={100,140,160,160};
  if(field==1)value=cpu[role]*1000;else if(field==3)value=memory[role];else if(field==5)value=pids[role];}
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0};
 memcpy(out,header,sizeof(header));unsigned int serial=241+field*4+role;out[20]=(unsigned char)serial;out[21]=(unsigned char)(serial>>8);
 out[32]=1;out[33]=field?'t':'b';out[34]=out[35]=0;memset(out+36,0,4);out[4]=(unsigned char)(field?16:8);
 size_t offset=field?40:36,count=field?8:4;for(size_t i=0;i<count;++i)out[offset+i]=(unsigned char)(value>>(8*i));return offset+count;
}
static const char *const fixture_cgroup_arrays[]={"DelegateControllers","DisableControllers"};
static size_t fixture_cgroup_array_reply(unsigned char *out,unsigned int field,unsigned int role)
{
 assert(field<2&&role<4);static const unsigned char empty[]={'l',2,1,1,8,0,0,0,13,0,0,0,15,0,0,0,
     5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,2,'a','s',0,0,0,0,0};
 static const unsigned char controllers[]={3,0,0,0,'c','p','u',0,6,0,0,0,'m','e','m','o','r','y',0,0,4,0,0,0,'p','i','d','s',0};
 memcpy(out,empty,sizeof(empty));unsigned int serial=265+field*4+role;out[20]=(unsigned char)serial;out[21]=(unsigned char)(serial>>8);
 if(!field&&!role){out[4]=37;out[36]=sizeof(controllers);memcpy(out+40,controllers,sizeof(controllers));return 40+sizeof(controllers);}
 return sizeof(empty);
}
static size_t fixture_cgroup_id_reply(unsigned char *out,unsigned int role)
{
 assert(role<4);static const unsigned char message[]={'l',2,1,1,16,0,0,0,13,0,0,0,15,0,0,0,
     5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,1,'t',0,0,0,0,0,0,0,16,0,0,0x78,0x56,0x34,0x12};
 memcpy(out,message,sizeof(message));unsigned int serial=273+role;out[20]=(unsigned char)serial;out[21]=(unsigned char)(serial>>8);
 out[40]=(unsigned char)role;return sizeof(message);
}
static void fixture_check_property_interface(const void *raw,size_t length,unsigned int index,const char *interface,const char *property,unsigned int serial)
{
 const unsigned char *b=raw;assert(index<4);size_t path=strlen(fixture_unit_objects[index]);
 size_t pos=24+path+1;while(pos%8)++pos;
 size_t fields=pos+40+16+8-16,body=16+fields;
 size_t property_length=strlen(property),interface_length=strlen(interface);
 size_t interface_wire=(4+interface_length+1+3)&~(size_t)3,body_length=interface_wire+5+property_length;
 assert(body%8==0&&length==body+body_length);
 assert(!memcmp(b,"l\1\2\1",4)&&b[4]==body_length&&!b[5]&&!b[6]&&!b[7]&&b[8]==(serial&255)&&b[9]==((serial>>8)&255)&&!b[10]&&!b[11]);
 assert(b[12]==fields&&!b[13]&&!b[14]&&!b[15]&&b[16]==1&&b[17]==1&&b[18]=='o'&&!b[19]&&b[20]==path&&!b[21]&&!b[22]&&!b[23]);
 assert(!memcmp(b+24,fixture_unit_objects[index],path+1));
 for(size_t i=25+path;i<pos;++i)assert(!b[i]);
 static const unsigned char prop[]={2,1,'s',0,31,0,0,0};
 assert(!memcmp(b+pos,prop,sizeof(prop))&&!memcmp(b+pos+8,"org.freedesktop.DBus.Properties",32));pos+=40;
 static const unsigned char member[]={3,1,'s',0,3,0,0,0,'G','e','t',0,0,0,0,0};
 assert(!memcmp(b+pos,member,sizeof(member)));pos+=16;
 static const unsigned char signature[]={8,1,'g',0,2,'s','s',0};
 assert(!memcmp(b+pos,signature,sizeof(signature)));pos+=8;
 assert(pos==body&&b[pos]==interface_length&&!b[pos+1]&&!b[pos+2]&&!b[pos+3]);pos+=4;
 assert(!memcmp(b+pos,interface,interface_length+1));pos+=interface_length+1;
 while(pos%4){assert(!b[pos]);++pos;}
 assert(b[pos]==property_length&&!b[pos+1]&&!b[pos+2]&&!b[pos+3]&&!memcmp(b+pos+4,property,property_length+1));
}
static void fixture_check_property(const void *raw,size_t length,unsigned int index,const char *property,unsigned int serial)
{fixture_check_property_interface(raw,length,index,"org.freedesktop.systemd1.Unit",property,serial);}
static void fixture_check_id(const void *raw,size_t length,unsigned int index)
{fixture_check_property(raw,length,index,"Id",3+index);}
static size_t fixture_id_reply(unsigned char *out,unsigned int index)
{
 assert(index<4);size_t n=strlen(fixture_unit_names[index]);
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,1,'s',0,0};
 memcpy(out,header,sizeof(header));out[4]=(unsigned char)(9+n);out[20]=(unsigned char)(3+index);
 out[36]=(unsigned char)n;out[37]=out[38]=out[39]=0;memcpy(out+40,fixture_unit_names[index],n+1);
 return 41+n;
}
static size_t fixture_names_reply(unsigned char *out,unsigned int index)
{
 assert(index<4);size_t n=strlen(fixture_unit_names[index]);
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,2,'a','s',0};
 memcpy(out,header,sizeof(header));out[4]=(unsigned char)(13+n);out[20]=(unsigned char)(7+index);
 out[36]=(unsigned char)(5+n);out[37]=out[38]=out[39]=0;out[40]=(unsigned char)n;out[41]=out[42]=out[43]=0;
 memcpy(out+44,fixture_unit_names[index],n+1);return 45+n;
}
static const char *const fixture_unit_field_names[]={"LoadState","ActiveState","SubState","FragmentPath","SourcePath",
    "CollectMode","JobTimeoutAction","FailureAction","SuccessAction","StartLimitAction"};
static size_t fixture_unit_field_reply(unsigned char *out,unsigned int field,unsigned int role)
{
 assert(field<10&&role<4);char value[128];const char *v;
 if(field==0)v="loaded";else if(field==1)v="active";else if(field==2)v=role?"active":"running";
 else if(field==3){static const char prefix[]="/etc/systemd/system/";size_t n=strlen(fixture_unit_names[role]);
  assert(sizeof(prefix)+n<=sizeof(value));memcpy(value,prefix,sizeof(prefix)-1);memcpy(value+sizeof(prefix)-1,fixture_unit_names[role],n+1);v=value;}
 else if(field==4)v="";else if(field==5)v="inactive";else v="none";
 size_t n=strlen(v);static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,1,'s',0,0};
 memcpy(out,header,sizeof(header));out[4]=(unsigned char)(9+n);out[20]=(unsigned char)(11+field*4+role);
 out[36]=(unsigned char)n;out[37]=out[38]=out[39]=0;memcpy(out+40,v,n+1);return 41+n;
}
static const char *const fixture_unit_bool_names[]={"NeedDaemonReload","Transient","DefaultDependencies",
    "RefuseManualStart","RefuseManualStop","IgnoreOnIsolate","StopWhenUnneeded"};
static size_t fixture_unit_bool_reply(unsigned char *out,unsigned int field,unsigned int role)
{
 assert(field<7&&role<4);
 static const unsigned char message[]={'l',2,1,1,8,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,
     8,1,'g',0,1,'v',0,0,1,'b',0,0,0,0,0,0};
 memcpy(out,message,sizeof(message));out[20]=(unsigned char)(51+field*4+role);
 out[36]=(field==4||field==5)?1:0;return sizeof(message);
}
static const char *const fixture_unit_fact_names[]={"InvocationID","Job"};
static size_t fixture_unit_fact_reply(unsigned char *out,unsigned int field,unsigned int role)
{
 assert(field<2&&role<4);
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0};
 memcpy(out,header,sizeof(header));out[20]=(unsigned char)(79+field*4+role);
 if(!field){static const unsigned char body[]={2,'a','y',0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  memcpy(out+32,body,sizeof(body));out[4]=sizeof(body);out[42]=(unsigned char)(1+role);return 32+sizeof(body);}
 static const unsigned char body[]={4,'(','u','o',')',0,0,0,0,0,0,0,1,0,0,0,'/',0};
 memcpy(out+32,body,sizeof(body));out[4]=sizeof(body);return 32+sizeof(body);
}
static const char *const fixture_unit_dependency_names[]={"DropInPaths","Requires","Requisite","BindsTo","PartOf","ConsistsOf",
    "Conflicts","ConflictedBy","Before","After","OnFailure","OnSuccess","PropagatesStopTo","StopPropagatedFrom",
    "Triggers","TriggeredBy","RequiresMountsFor","Upholds","OnFailureOf","OnSuccessOf"};
static size_t fixture_unit_dependency_reply(unsigned char *out,unsigned int field,unsigned int role)
{
 assert(field<20&&role<4);const char *value=NULL;
 if(field==1||field==9)value=role==0?fixture_unit_names[1]:role==3?fixture_unit_names[2]:"-.slice";
 else if(field==8)value=role==1?fixture_unit_names[0]:role==2?fixture_unit_names[3]:NULL;
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,2,'a','s',0,0,0,0,0};
 memcpy(out,header,sizeof(header));out[20]=(unsigned char)(87+field*4+role);
 if(!value){out[4]=8;return 40;}
 size_t n=strlen(value);out[4]=(unsigned char)(13+n);out[36]=(unsigned char)(5+n);
 out[40]=(unsigned char)n;out[41]=out[42]=out[43]=0;memcpy(out+44,value,n+1);return 45+n;
}
static const char *const fixture_unit_timeout_names[]={"JobTimeoutUSec","JobRunningTimeoutUSec"};
static size_t fixture_unit_timeout_reply(unsigned char *out,unsigned int field,unsigned int role)
{
 assert(field<2&&role<4);static const unsigned char message[]={'l',2,1,1,16,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,
     8,1,'g',0,1,'v',0,0,1,'t',0,0,0,0,0,0,255,255,255,255,255,255,255,255};
 memcpy(out,message,sizeof(message));out[20]=(unsigned char)(167+field*4+role);return sizeof(message);
}
static const char *const fixture_service_field_names[]={"Type","ExitType","Restart","RestartMode","OOMPolicy","NotifyAccess","PIDFile",
    "TimeoutStartFailureMode","TimeoutStopFailureMode","User","Group","RootDirectory","RootImage","WorkingDirectory",
    "StandardInput","StandardOutput","StandardError","PAMName","BusName","KillMode"};
static const char *const fixture_service_field_values[]={"exec","cgroup","no","normal","continue","none","",
    "terminate","terminate","root","root","","","","null","null","null","","","process"};
static size_t fixture_service_field_reply(unsigned char *out,unsigned int field)
{
 assert(field<20);const char *v=fixture_service_field_values[field];size_t n=strlen(v);
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0,1,'s',0,0};
 memcpy(out,header,sizeof(header));out[4]=(unsigned char)(9+n);out[20]=(unsigned char)(175+field);
 out[36]=(unsigned char)n;out[37]=out[38]=out[39]=0;memcpy(out+40,v,n+1);return 41+n;
}
static const char *const fixture_service_scalar_names[]={"RemainAfterExit","DynamicUser","SendSIGKILL","SendSIGHUP",
    "RuntimeMaxUSec","RuntimeRandomizedExtraUSec","WatchdogUSec","LimitNOFILE","LimitNOFILESoft",
    "MainPID","ControlPID","NRestarts","FileDescriptorStoreMax","NFileDescriptorStore"};
static size_t fixture_service_scalar_reply(unsigned char *out,unsigned int field,unsigned int keeper)
{
 assert(field<14);char type=field<4?'b':field<9?'t':'u';uint64_t value=field==4?UINT64_MAX:
     (field==7||field==8)?256:field==9?keeper:0;
 static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0};
 memcpy(out,header,sizeof(header));out[20]=(unsigned char)(195+field);out[32]=1;out[33]=(unsigned char)type;out[34]=out[35]=0;
 size_t offset=type=='t'?40:36,count=type=='t'?8:4;memset(out+36,0,4);out[4]=(unsigned char)(type=='t'?16:8);
 for(size_t i=0;i<count;++i)out[offset+i]=(unsigned char)(value>>(8*i));
 return offset+count;
}
static const char *const fixture_service_empty_names[]={"Environment","EnvironmentFiles","PassEnvironment","UnsetEnvironment",
    "RestartForceExitStatus","ExecConditionEx","ExecStartPreEx","ExecStartPostEx","ExecReloadEx","ExecStopEx","ExecStopPostEx"};
static size_t fixture_service_empty_reply(unsigned char *out,unsigned int field)
{
 assert(field<11);static const unsigned char header[]={'l',2,1,1,0,0,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0,0};
 static const unsigned char as[]={2,'a','s',0,0,0,0,0};
 static const unsigned char asb[]={5,'a','(','s','b',')',0,0,0,0,0,0,0,0,0,0};
 static const unsigned char aiai[]={6,'(','a','i','a','i',')',0,0,0,0,0,0,0,0,0};
 static const unsigned char exec[]={15,'a','(','s','a','s','a','s','t','t','t','t','u','i','i',')',0,0,0,0,0,0,0,0};
 const unsigned char *body=field==1?asb:field==4?aiai:field>=5?exec:as;
 size_t n=field==1?sizeof(asb):field==4?sizeof(aiai):field>=5?sizeof(exec):sizeof(as);
 memcpy(out,header,sizeof(header));out[4]=(unsigned char)n;out[20]=(unsigned char)(209+field);memcpy(out+32,body,n);return 32+n;
}
static size_t fixture_service_exec_reply(unsigned char *out,unsigned int keeper,const char *native_hash)
{
 static const unsigned char header[]={'l',2,1,1,28,1,0,0,13,0,0,0,15,0,0,0,5,1,'u',0,220,0,0,0,8,1,'g',0,1,'v',0,0};
 static const unsigned char signature[]={15,'a','(','s','a','s','a','s','t','t','t','t','u','i','i',')',0,0,0,0};
 static const char prefix[]="/usr/lib/rnr/bootstraps/",suffix[]="/rnr-stage0";
 char path[100];assert(strlen(native_hash)==64);memcpy(path,prefix,sizeof(prefix)-1);memcpy(path+sizeof(prefix)-1,native_hash,64);
 memcpy(path+sizeof(prefix)-1+64,suffix,sizeof(suffix));assert(strlen(path)==99);
 memset(out,0,316);memcpy(out,header,sizeof(header));memcpy(out+32,signature,sizeof(signature));
 out[52]=4;out[53]=1;out[56]=99;memcpy(out+60,path,100);
 out[160]=104;out[164]=99;memcpy(out+168,path,100);out[272]=1;out[280]=2;
 out[304]=(unsigned char)keeper;out[305]=(unsigned char)(keeper>>8);out[306]=(unsigned char)(keeper>>16);out[307]=(unsigned char)(keeper>>24);
 return 316;
}
#undef FIXTURE_PROJECT
static void fixture_check_lookup(const void *raw,size_t length,unsigned int keeper)
{
 const unsigned char *b=raw;assert(length==140&&!memcmp(b,fixture_lookup_request,sizeof(fixture_lookup_request)));
 assert(b[136]==(keeper&255)&&b[137]==((keeper>>8)&255)&&b[138]==((keeper>>16)&255)&&b[139]==((keeper>>24)&255));
}
static void fixture_lookup_reply(unsigned char out[146],int reverse)
{
 static const unsigned char header[16]={0x6c,2,1,1,0x72,0,0,0,12,0,0,0,15,0,0,0};
 static const unsigned char fields[16]={5,1,'u',0,1,0,0,0,8,1,'g',0,1,'o',0,0};
 static const unsigned char other[16]={8,1,'g',0,1,'o',0,0,5,1,'u',0,1,0,0,0};
 assert(sizeof(fixture_lookup_path)-1==109);memcpy(out,header,16);if(reverse)out[12]=16;
 memcpy(out+16,reverse?other:fields,16);out[32]=109;out[33]=out[34]=out[35]=0;
 memcpy(out+36,fixture_lookup_path,sizeof(fixture_lookup_path));
}
