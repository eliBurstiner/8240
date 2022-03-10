#include "pin.H"

#define MAIN "main"
#define FILENO "fileno"

// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"

using namespace std;

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <iostream>
#include <map>
#include <iterator>
#include <vector>

map<char*, bool> memMap;
vector<VOID*>stack;
map<char*, vector<VOID*> > stackTrace;
map<char*, char*> taintOrigin;

typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;

INT32 Usage()
{
  return -1;
}
  
bool isStdin(FILE *fd)
{
		int ret = org_fileno(fd);
		if(ret == 0) return true;
		return false;
}

//void printfTail(){
//  cout << "heyo" << endl;
//  stack.pop_back();
//  stack.pop_back();
//}

bool fgets_stdin = false;
VOID fgetsTail()
{
  stack.pop_back();
 		if(fgets_stdin) {
		  //		   				printf("fgetsTail: ret %p\n", ret);
		}
		fgets_stdin = false;
}

VOID fgetsHead(char* dest, int size, FILE *stream)
{
  char* temp = dest;
  if(isStdin(stream)) {
		  for(int i = 0; i < size; i++){
		    memMap[temp] = true;
		    stackTrace[temp++] = stack;
		  }
		  //printf("fgetsHead: dest %p, size %d, stream: stdin)\n", dest, size);
				fgets_stdin = true;
		} 
}

VOID getsTail(char* dest)
{
  char* temp =  dest;
  for(uint i = 0; i < strlen(dest); i++){
    memMap[temp] =  true;
    stackTrace[temp++] = stack;
}
  stack.pop_back();
  // printf("getsTail: dest %p)\n", dest);
  // printf("size of dest: %d\n", strlen(dest));
}

VOID mainHead(int argc, char** argv, ADDRINT inst)
{
  char* temp;
  for(int i = 0; i < argc; i++) {
    temp = argv[i];
    
    for(uint j = 0; j < strlen(argv[i]); j++){
      memMap[temp] = true;
      stackTrace[temp++] = stack;
    }
  }
}

VOID strcpyHead(char* dest, char* src)
{
  char* temp1 = src;
  char* temp2 = dest;
  for(uint i = 0; i < strlen(src); i++){
    if(memMap[temp1]){
      memMap[temp2] = true;
      stackTrace[temp2] = stack;
      taintOrigin[temp2] = temp1;
    }
    temp1++;
    temp2++;
  }
}

VOID strncpyHead(char* dest, char* src, size_t num)
{
  char* temp1 = src;
  char* temp2 = dest;
  for(uint i = 0; i < num; i++){
    if(memMap[temp1]){
      memMap[temp2] = true;
      stackTrace[temp2] = stack;
      taintOrigin[temp2] = temp1;
    }
    temp1++;
    temp2++;
  }
}

VOID strcatHead(char* dest, char* src)
{
  uint offset = strlen(dest);
  char* temp1 = src;
  char* temp2 = dest;
  for(uint i = 0; i < strlen(src); i++){  
    if(memMap[temp1]){
      memMap[temp2 + offset] = true;
      stackTrace[temp2 + offset] = stack;
      taintOrigin[temp2 + offset] = temp1;
    }
    temp1++;
    temp2++;
  }
}

VOID strncatHead(char* dest, char* src, size_t num)
{
  uint offset = strlen(dest);
  char* temp1 = src;
  char* temp2 = dest;
  for(uint i = 0; i < num; i++){
    if(memMap[temp1]){
      memMap[temp2 + offset] = true;
      stackTrace[temp2 + offset] = stack;
      taintOrigin[temp2 + offset] = temp1;
    }
    temp1++;
    temp2++;
  }
}

VOID memcpyHead(char* dest, char* src, size_t num)
{
  char* temp1 = src;
  char* temp2 = dest;
  for(uint i = 0; i < num; i++){
    if(memMap[temp1]){
      memMap[temp2] = true;
      stackTrace[temp2] = stack;
      taintOrigin[temp2] = temp1;
    }
    temp1++;
    temp2++;
  }
}
VOID bzeroHead(void* dest, int n)
{
  char* temp = (char*)dest;
  for(int i = 0; i < n; i++){
    memMap[temp++] = false;  
  }
}

VOID memsetHead(void* dest, int c, size_t n)
{
  char* temp = (char*)dest;
  for(uint i = 0; i < n; i++){
    memMap[temp++] = false;
  }
}

VOID controlInsHead(ADDRINT inst, ADDRINT src, ADDRINT dest)
{
  void * instptr = Addrint2VoidStar(inst);
  void * srcptr = Addrint2VoidStar(src);
  void * destptr = Addrint2VoidStar(dest);
if(memMap[(char *) srcptr]){
  cout << "**************** Attack Detected *******************\nIndirectBranch(" << instptr <<"): jump to " << destptr <<", stored in tainted byte("<< srcptr <<")" << endl;
   void* tempptr = srcptr;
   for(int i = 0; tempptr != (char*)0x00000000; i++){
     cout << "Stack " << i << ": History of Mem(" << tempptr << "): ";
     for (vector<void*>::iterator it = stackTrace[(char*)tempptr].begin(); it != stackTrace[(char*)tempptr].end(); ++it) {
       cout << *it << ", ";
     }
     cout << endl;
     tempptr = taintOrigin[(char*) tempptr];
   }
   cout << "******************************************************" << endl;
PIN_ExitApplication(1);
 }
}

VOID Image(IMG img, VOID *v) {
  RTN rtn;
	        rtn = RTN_FindByName(img, FGETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);

				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail, 
							        IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, GETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail, 
								//IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					       IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, STRNCPY);
                if(RTN_Valid(rtn)) {
		  RTN_Open(rtn);
		  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				 IARG_END);
		  RTN_Close(rtn);
                }
		rtn = RTN_FindByName(img, STRCAT);
                if(RTN_Valid(rtn)) {
		  RTN_Open(rtn);
		  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				 IARG_END);
		  RTN_Close(rtn);
                }
		rtn = RTN_FindByName(img, STRNCAT);
                if(RTN_Valid(rtn)) {
		  RTN_Open(rtn);
		  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				 IARG_END);
		  RTN_Close(rtn);
                }
		rtn = RTN_FindByName(img, MEMCPY);
                if(RTN_Valid(rtn)) {
		  RTN_Open(rtn);
		  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				 IARG_END);
		  RTN_Close(rtn);
                }

		rtn = RTN_FindByName(img, BZERO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}
                rtn = RTN_FindByName(img, MEMSET);
                if(RTN_Valid(rtn)) {
                  RTN_Open(rtn);
                  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memsetHead,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                 IARG_END);
                  RTN_Close(rtn);
                }

		rtn = RTN_FindByName(img, MAIN);
        	if(RTN_Valid(rtn)) {
        			RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					       IARG_INST_PTR,
					     
								IARG_END);
				RTN_Close(rtn);
		}


		rtn = RTN_FindByName(img, FILENO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				AFUNPTR fptr = RTN_Funptr(rtn);
				org_fileno = (FP_FILENO)(fptr);
				RTN_Close(rtn);
		}
}


VOID Instruction(INS ins, VOID* v)
{
  if(INS_IsRet(ins)){
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(controlInsHead),
		   IARG_INST_PTR, 
		   IARG_MEMORYOP_EA, 0,
		   IARG_BRANCH_TARGET_ADDR,
		   IARG_END);
  }
}


void Trace(TRACE trace, void *v) {
  static bool mainDiscovered = false;
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
      RTN rtn = INS_Rtn(ins);
      if(RTN_Valid(rtn) && IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn)))){
	if(RTN_Name(rtn).compare("main") == 0 && !mainDiscovered){
	  stack.push_back(Addrint2VoidStar(INS_Address(ins)));
	  mainDiscovered = true;
	}	
	if( INS_IsDirectCall(ins) && RTN_Valid(RTN_FindByAddress(INS_DirectControlFlowTargetAddress(ins))) && RTN_Name(RTN_FindByAddress(INS_DirectControlFlowTargetAddress(ins))).compare("printf@plt") != 0){ 
	  stack.push_back(Addrint2VoidStar(INS_Address(ins)));
	}
	if( INS_IsRet(ins)){ 
	  stack.pop_back();
	}
      }
    }
  }
}

int main(int argc, char *argv[])
{
  PIN_InitSymbols();

		if(PIN_Init(argc, argv)){
		  return Usage();
		}
  IMG_AddInstrumentFunction(Image, 0);
  INS_AddInstrumentFunction(Instruction, 0);
  TRACE_AddInstrumentFunction(Trace,0);
		PIN_StartProgram();

		return 0;
}

