/*  This file is part of Fuzzgrind.
 *  Copyright (C) 2009 Gabriel Campana
 *  
 *  Based heavily on Flayer by redpig@dataspill.org
 *  Copyright (C) 2006,2007 Will Drewry <redpig@dataspill.org>
 *  Some portions copyright (C) 2007 Google Inc.
 * 
 *  Based heavily on MemCheck by jseward@acm.org
 *  MemCheck: Copyright (C) 2000-2007 Julian Seward
 *  jseward@acm.org
 * 
 * 
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307, USA.
 *  
 *  The GNU General Public License is contained in the file LICENCE.
 */


#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_mallocfree.h"
#include "fz.h"
#include "global.h"
static mycounter=0;
static check_1=0;
static int tx=0;
static Addr ebp=0;
static Char func_name[100];
struct Stack_Vars
{
	Addr addr;
	int len;
	Bool isTainted;
	Char fn_name[100];
	int maxlen;
	struct Stack_Vars *next;
};

static struct Stack_Vars *sthead =NULL;

int AddStack(Addr addr, int len, Bool isTainted)
{
	int swch1;
	swch1=0;
	/*if (len >0){
		return 0;
	}*/
	if (len <0){
		swch1=1;
		//VG_(printf)("len is %d \n", len);
		len=len *(-1);
		//VG_(printf)("now len is %d \n", len);
	}
	struct Stack_Vars *var ;
	var = (struct Stack_Vars*) VG_(malloc)("Stack_Var",sizeof(struct Stack_Vars));
	var->addr = addr;
	var->maxlen = len;
	var->len = len;
	var->isTainted = isTainted;
	VG_(strcpy)(var->fn_name,func_name);
	var->next=NULL;
	if (sthead == NULL)
	{
		sthead = var;
		//VG_(printf)("addr %x is added first \n", addr);
		return 0;

	}
	else
	{
		//Find the last element
		struct Stack_Vars *cur;
		struct Stack_Vars *cur_next;
		struct Stack_Vars *cur_before;
		cur = sthead;
		if (cur->next==NULL){
			if (cur->addr ==addr){
				return 0;
			}
			if (addr > cur->addr){
				if(!VG_(strcmp)(cur->fn_name, var->fn_name) && swch1==1){
						cur->len=cur->maxlen -var->maxlen;
						//VG_(printf)("addr %x is in the same fn len is %d cur len is %d and the max len is %d cur add is %x\n", addr, var->len,cur->len, var->maxlen,cur->addr);
				}
				var->next=cur;
				sthead=var;
				//VG_(printf)("addr %x is added as the head\n", addr);
				return 0;
			}
		}

		cur_before = NULL;
		cur = sthead;
		while (cur != NULL)
		{

			if ((var ->addr >=cur->addr && var->addr <=(cur->addr +cur->maxlen) && VG_(strcmp)(cur->fn_name, var->fn_name))
				||
				(cur->addr >= var->addr && cur->addr <= (var->addr +var->maxlen) && VG_(strcmp)(cur->fn_name, var->fn_name))
				||
				((var ->addr+ var->maxlen) >=cur->addr && (var->addr+var->maxlen) <=(cur->addr +cur->maxlen) && VG_(strcmp)(cur->fn_name, var->fn_name)))
			{
				//VG_(printf)("addr %x is equal to curr addr %x \n", addr, cur->addr);
				//return 0;
				//removing the 1st element
				if (cur_before == NULL)
				{
					//VG_(printf)("removing the first element; addr: %x \n" ,sthead->addr);
					cur_before = sthead;
					sthead= sthead->next;
					VG_(free)(cur_before);
					cur_before = NULL;
					cur = sthead;
				}
				//Removing the cur element
				else
				{
					//VG_(printf)("removing cur element; addr = %x \n" , cur->addr);
					cur_before->next = cur->next;
					VG_(free)(cur);
					cur = cur_before->next;
				}
			}
			else
			{
				cur_before = cur;
				cur=cur->next;
			}
		}
		cur=sthead;
		while (cur->next != NULL)
				{
			if (cur->addr < addr){
				//VG_(printf)("addr %x is added at the head\n", addr);
				if ( swch1==1){
				cur->len=cur->maxlen-var->maxlen;}
				sthead=var;
				var->next=cur;
				return 0;

			}
			if (cur->addr > addr && cur->next->addr <= addr){
				if(!VG_(strcmp)(cur->fn_name, var->fn_name) && swch1==1){
										var->len=var->maxlen-cur->maxlen;
										//VG_(printf)("addr %x is in the same fn len is %d cur len is %d and max len is %d\n", addr, var->len,cur->len, var->maxlen);
								}
				if(!VG_(strcmp)(cur->next->fn_name, var->fn_name) && swch1==1){
														cur->next->len=cur->next->maxlen-var->maxlen;
														//VG_(printf)("addr %x is in the same fn len is %d next len is %d and max len is %d \n", addr, var->len,cur->next->len, var->maxlen);
												}
				cur_next=cur->next;
				cur->next=var;
				var->next=cur_next;
				//VG_(printf)("addr %x is less than addr %x \n", addr, cur->addr);
				//VG_(printf)("addr %x is added in the middle\n", addr);

				return 0;
			}

			cur = cur->next;
		}
		if(!VG_(strcmp)(cur->fn_name, var->fn_name)&& swch1==1){
										var->len=var->maxlen-cur->maxlen;
										//VG_(printf)("addr %x is in the same fn len is %d cur len is %d and max len is \n", addr, var->len,cur->len, var->maxlen);
								}
		cur->next = var;
		//VG_(printf)("addr %x is added in the end\n", addr);

	}
}

struct Vul_Spec
{
	int tag; //0 for IRStmt and 1 for IRExpr
	union
	{
		IRStmt Ist_Container;
		IRExpr Iex_Container;
	} Container;

	char* rule;
} Vuls_DB[100];


static IRExpr *assignNew(IRSB *bb, IRExpr *e) {
IRTemp t = newIRTemp(bb->tyenv, Ity_I32);
  IRTemp t2 = newIRTemp(bb->tyenv, Ity_I64);
  IRStmt *st1;
  st1=(IRStmt*) VG_(malloc)("IRStmt", sizeof(IRStmt));
  IRExpr *e2;
  e2=(IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
  switch (typeOfIRExpr(bb->tyenv, e)) {

     case Ity_I1:
      addStmtToIRSB(bb, IRStmt_WrTmp(t, IRExpr_Unop(Iop_1Uto32, e)));

      break;

    case Ity_I8:
      addStmtToIRSB(bb, IRStmt_WrTmp(t, IRExpr_Unop(Iop_8Uto32, e)));

      break;
    case Ity_I16:
      addStmtToIRSB(bb, IRStmt_WrTmp(t, IRExpr_Unop(Iop_16Uto32, e)));

      break;
    case Ity_I32:

      return e;
    case Ity_I64:

      addStmtToIRSB(bb, IRStmt_WrTmp(t, IRExpr_Unop(Iop_64to32, e)));
      break;
    case Ity_V128:
    	st1=IRStmt_WrTmp(t2, IRExpr_Unop(Iop_V128to64, e));

        addStmtToIRSB(bb, st1);
        st1=IRStmt_WrTmp(t, IRExpr_Unop(Iop_64to32, IRExpr_RdTmp(t2)));
        addStmtToIRSB(bb, st1);
          break;
      //case Ity_F64:
      //    addStmtToIRSB(bb, IRStmt_WrTmp(t, IRExpr_Unop(Iop_F64toI32, e)));
      //    break;
    default:

      VG_(tool_panic)("assignNew");
	break;
  }
  return IRExpr_RdTmp(t);
}





#ifdef FZ_DEBUG
static void ppDepReg(Dep *reg) {
  //VG_(printf)("    reg    = %d\n", reg->value.reg);
  VG_(printf)("    size   = %d\n", reg->size);
  VG_(printf)("    constr = %s\n", reg->cons);
}


static void ppDepTmp(Dep *tmp) {
  VG_(printf)("    size   = %d\n", tmp->size);
  VG_(printf)("    constr = %s\n", tmp->cons);
}


static void ppDepAddr(Dep *addr) {
  VG_(printf)("    addr   = 0x%08x\n", (UInt)addr->value.addr);
  VG_(printf)("    size   = %d\n", addr->size);
  VG_(printf)("    constr = %s\n", addr->cons);
}
#else
#define ppDepReg(x)
#define ppDepTmp(x)
#define ppDepAddr(x)
#endif


//#define FZ_DEBUG
/*
 * Check that the size of the constraint buffer is large enough to contain the
 * new string. If not, reallocate the buffer.
 */
static void realloc_cons_buf(Dep *d, UInt new_size) {
  d->cons_size *= 2;
  tl_assert(new_size < d->cons_size);

  if (d->cons == d->buf) {
    d->cons = VG_(malloc)("fz.rcb.1", d->cons_size);
  }
  else {
    d->cons = VG_(realloc)("fz.rcb.2", d->cons, d->cons_size); 
  }

  tl_assert(d->cons != NULL);
}


static void free_cons_buf(Dep *d) {
  if (d->cons != d->buf) {
    VG_(free)(d->cons);
    d->cons = d->buf;
    d->cons_size = XXX_MAX_BUF;
  }
  d->cons[0] = '\x00';
}

#define SPRINTF_CONS(d, fmt, ...) do {                                                 \
  UInt res_snprintf;                                                                 \
  Bool ok = True;                                                                    \
  do {                                                                               \
    res_snprintf = VG_(snprintf)((d).cons, (d).cons_size, (fmt), __VA_ARGS__);     \
    if (res_snprintf >= (d).cons_size - 1) { /* valgrind's buggy snprintf... */    \
      realloc_cons_buf(&(d), res_snprintf);                                      \
      res_snprintf = VG_(snprintf)((d).cons, (d).cons_size, (fmt), __VA_ARGS__); \
      ok = (res_snprintf < (d).cons_size - 1);                                   \
    }                                                                              \
  } while (!ok);                                                                     \
} while (0)


static UInt add_dependency_reg(Reg reg, UInt size) {
  tl_assert(reg >= 0 && reg < MAX_DEP);
  tl_assert(size != 0);
  depreg[reg].size = size;

#ifdef FZ_DEBUG
  VG_(printf)("[+] dependency_reg[%d]\n", reg);
#endif

  return reg;
}

static UInt add_dependency_tmp(Tmp tmp, UInt size) {
  tl_assert(tmp >= 0 && tmp < MAX_DEP); 
  deptmp[tmp].size = size;

#ifdef FZ_DEBUG
  VG_(printf)("[+] dependency_tmp[%d]\n", tmp);
#endif

  return tmp;
}

UInt add_dependency_addr(Addr addr, UInt size) {
  UInt i;
  Dep *depaddr = SELECT_DEPADDR(size);
  UInt *depaddr_count = SELECT_DEPADDR_COUNT(size);

  /* search for an existing dependency and replace it */
  for (i = 0; i < *depaddr_count; i++) {
    if (depaddr[i].value.addr == addr) {
    	VG_(printf)("[+] dependency_addr[%d] addr[%08x] matched\n", i, addr);
      break;
    }
  }

  tl_assert(i < MAX_DEP);
  if (i == *depaddr_count) {
    depaddr[i].value.addr = addr;
    *depaddr_count += 1;
  }
  tl_assert(size != 0);
  depaddr[i].size = size;

  //VG_(printf)("[+] dependency_addr[%d] addr[%08x]\n", i, addr);

#ifdef FZ_DEBUG
  VG_(printf)("[+] dependency_addr[%d] addr[%08x]\n", i, addr);
#endif

  return i;
}

static void del_dependency_tmp(Tmp tmp) {
  tl_assert(tmp >= 0 && tmp < MAX_DEP);
  if (deptmp[tmp].cons[0] != '\x00') {
    free_cons_buf(&deptmp[tmp]);
  }
}

static void del_dependency_reg(Reg reg) {
  tl_assert(reg >= 0 && reg < MAX_DEP);
  if (depreg[reg].cons[0] != '\x00') {
    free_cons_buf(&depreg[reg]);
  }
}

void del_dependency_addr(Addr addr, UInt size) {
  Dep *depaddr = SELECT_DEPADDR(size);
  UInt *depaddr_count = SELECT_DEPADDR_COUNT(size);
  UInt i, j = *depaddr_count - 1;

  for (i = 0; i < *depaddr_count; i++) {
    if (depaddr[i].value.addr == addr) {
#ifdef FZ_DEBUG
      VG_(printf)("[+] removing dependency_addr[%d]\n", i);
      ppDepAddr(&depaddr[i]);
#endif
      free_cons_buf(&depaddr[i]);
      if (i < j) {
        depaddr[i].value.addr = depaddr[j].value.addr;
        depaddr[i].size = depaddr[j].size;
        SPRINTF_CONS(depaddr[i], "%s", depaddr[j].cons);
        free_cons_buf(&depaddr[j]);
      }
      *depaddr_count -= 1; 
      break;
    }
  }
}


char * depend_on_addr(Addr addr, UInt size) {
  UInt i;
  Dep *depaddr = SELECT_DEPADDR(size);
  UInt *depaddr_count = SELECT_DEPADDR_COUNT(size);
 // VG_(printf)("[+] addr [%08x] is \n", addr);
  /* search for an existing dependency and replace it */
  for (i = 0; i < *depaddr_count; i++) {
    if (depaddr[i].value.addr == addr) {
    	//VG_(printf)("[+] addr [%08x] found \n", addr);
      return depaddr[i].cons;
    }
  }

  return NULL;
}

static UInt depend_of_reg(Reg reg) {
  tl_assert(reg >= 0 && reg < MAX_DEP);
  return depreg[reg].cons[0] != '\x00';
}

static UInt depend_of_tmp(Tmp tmp) {
  tl_assert(tmp >= 0 && tmp < MAX_DEP);
  return deptmp[tmp].cons[0] != '\x00';
}


/*
 * Write a value to a register
 * tmp is invalid if it's a constant
 */
static VG_REGPARM(0) void helperc_put(Tmp tmp, Reg offset) {
  UInt j;

  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {
      j = add_dependency_reg(offset, deptmp[tmp].size);
      SPRINTF_CONS(depreg[j], "PUT(%s)", deptmp[tmp].cons);
      ppDepReg(&depreg[j]);
      return;
    }
  }
  del_dependency_reg(offset);
 }
  static VG_REGPARM(0) void helperc_put2(Tmp tmp, Reg offset) {
    UInt j;

    if (tmp != INVALID_TMP) {
      if (depend_of_tmp(tmp)) {
        //j = add_dependency_reg(offset, deptmp[tmp].size);
        //SPRINTF_CONS(depreg[j], "PUT(%s)", deptmp[tmp].cons);
        //ppDepReg(&depreg[j]);
    	 VG_(printf)("taint in the function for put instr %s \n", deptmp[tmp].cons );
        return;
      }
    }
  }

  /* delete an eventually dependency to the offset if:
   * - the value to write is a constant
   * - or we don't depend of the tmp */ 



/*
 * Valgrind does implicit size conversion between PUT and GET, so we can't rely
 * on the dependency's size. For example : GET:I32(PUT(1Uto8(a))).
 */
static VG_REGPARM(0) void helperc_get(Reg offset, Tmp tmp, UInt size) {
  UInt j;

  if (depend_of_reg(offset)) {
    j = add_dependency_tmp(tmp, size);
    SPRINTF_CONS(deptmp[j], "GET:I%d(%s)", size, depreg[offset].cons);
    ppDepTmp(&deptmp[j]);
    return;
  }

  del_dependency_tmp(tmp);
}

static VG_REGPARM(0) void helperc_get2(Reg offset, Tmp tmp, UInt size) {
  UInt j;

  if (depend_of_reg(offset)) {
    //j = add_dependency_tmp(tmp, size);
    //SPRINTF_CONS(deptmp[j], "GET:I%d(%s)", size, depreg[offset].cons);
    //ppDepTmp(&deptmp[j]);
 	 VG_(printf)("taint in the function for get instr %s \n", depreg[offset].cons );

    return;
  }


}

static VG_REGPARM(0) void helperc_load(Addr addr, Tmp tmp, Tmp tmp_to, UInt size) {
  UInt a, b, c, i, j, pos;

  if (addr != INVALID_ADDR) {
    if (size == 8) {
      for (i = 0; i < depaddr8_count; i++) {
        if (depaddr8[i].value.addr != addr) continue;

        if (VG_(strncmp)(depaddr8[i].cons, "input", 5) != 0 &&
            VG_(strncmp)(depaddr8[i].cons, "ST", 2) != 0) {
          break;
        }
        j = add_dependency_tmp(tmp_to, 8);
        SPRINTF_CONS(deptmp[j], "LDle:I%d(%s)", size, depaddr8[i].cons);
        ppDepTmp(&deptmp[j]);
        return;
      }

      for (i = 0; i < depaddr16_count; i++) {
        if (addr < depaddr16[i].value.addr
          || addr >= depaddr16[i].value.addr + 2)
          continue;
        pos = addr - depaddr16[i].value.addr;
        if (VG_(strncmp)(depaddr16[i].cons, "input", 5) != 0
            && VG_(strncmp)(depaddr16[i].cons, "ST", 2) != 0) {
          break;
        }
        j = add_dependency_tmp(tmp_to, 8);
        SPRINTF_CONS(deptmp[j],
            "32to8(And32(Shr32(8Uto32(LDle:I8(%s)),0x%x:I32),0xff:I32))",
            depaddr16[i].cons, 8 * pos);
        ppDepTmp(&deptmp[j]);
        return;
      }

      for (i = 0; i < depaddr32_count; i++) {
        if (addr < depaddr32[i].value.addr
          || addr >= depaddr32[i].value.addr + 4)
          continue;
        pos = addr - depaddr32[i].value.addr;
        if (VG_(strncmp)(depaddr32[i].cons, "input", 5) != 0
            && VG_(strncmp)(depaddr32[i].cons, "ST", 2) != 0) {
          break;
        }
        j = add_dependency_tmp(tmp_to, 8);
        SPRINTF_CONS(deptmp[j],
            "32to8(And32(Shr32(8Uto32(LDle:I8(%s)),0x%x:I32),0xff:I32))",
            depaddr32[i].cons, 8 * pos);
        ppDepTmp(&deptmp[j]);
        return;
      }
    }
    else if (size == 16) {
      for (i = 0; i < depaddr16_count; i++) {
        if (depaddr16[i].value.addr == addr) {
          if (VG_(strncmp)(depaddr16[i].cons, "input", 5) != 0 
            && VG_(strncmp)(depaddr16[i].cons, "ST", 2) != 0) {
            break;
          }
          j = add_dependency_tmp(tmp_to, 16);
          SPRINTF_CONS(deptmp[j], "LDle:I%d(%s)", size, depaddr16[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }

      for (i = 0; i < depaddr32_count; i++) {
        if (addr >= depaddr32[i].value.addr && addr <= depaddr32[i].value.addr + 2) {
          pos = addr - depaddr32[i].value.addr;
          if (VG_(strncmp)(depaddr32[i].cons, "input", 5) != 0 
            && VG_(strncmp)(depaddr32[i].cons, "ST", 2) != 0) {
            break;
          }
          j = add_dependency_tmp(tmp_to, 16);
          SPRINTF_CONS(deptmp[j], "32to16(And32(Shr32(16Uto32(LDle:I16(%s)),0x%x:I32),0xffff:I32))", depaddr32[i].cons, 8 * pos);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }

      for (i = 0; i < depaddr8_count; i++) {
        if (depaddr8[i].value.addr == addr) {
          for (a = 0; a < depaddr8_count; a++) {
            if (depaddr8[a].value.addr == addr + 1) {
              break;
            }
          }
          // khodam agar assert fail konad return mikonim (SQL I)
          if (a == depaddr8_count){
        	  return;
          }
          tl_assert(a != depaddr8_count);

          j = add_dependency_tmp(tmp_to, 16);

          SPRINTF_CONS(deptmp[j], "Cat16(LDle:I8(%s),LDle:I8(%s))", depaddr8[a].cons, depaddr8[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }
    }
    else if (size == 32) {
      for (i = 0; i < depaddr32_count; i++) {
        if (depaddr32[i].value.addr == addr) {
          if (VG_(strncmp)(depaddr32[i].cons, "input", 5) != 0 && VG_(strncmp)(depaddr32[i].cons, "ST", 2) != 0) {
            break;
          }
          j = add_dependency_tmp(tmp_to, 32);
          SPRINTF_CONS(deptmp[j], "LDle:I32(%s)", depaddr32[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }

      for (i = 0; i < depaddr8_count; i++) {
        if (depaddr8[i].value.addr == addr) {
          for (a = 0; a < depaddr8_count; a++) {
            if (depaddr8[a].value.addr == addr + 1) {
              break;
            }
          }
          for (b = 0; b < depaddr8_count; b++) {
            if (depaddr8[b].value.addr == addr + 2) {
              break;
            }
          }
          for (c = 0; c < depaddr8_count; c++) {
            if (depaddr8[c].value.addr == addr + 3) {
              break;
            }
          }
          // XXX
          //tl_assert(a != depaddr8_count && b != depaddr8_count && c != depaddr8_count);
          if (!(a != depaddr8_count && b != depaddr8_count && c != depaddr8_count)) {
            continue;
          }

          j = add_dependency_tmp(tmp_to, 32);
          SPRINTF_CONS(deptmp[j],
              "Cat32(LDle:I8(%s),Cat24(LDle:I8(%s),Cat16(LDle:I8(%s),LDle:I8(%s))))",
              depaddr8[c].cons,
              depaddr8[b].cons,
              depaddr8[a].cons,
              depaddr8[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }
    }
    else if (size == 64) {
      // XXX - currently not supported...
      //VG_(printf)("oops, size = 64\n");
    }
    else {
    	//khodam to escape V128 panic
      //VG_(printf)("size = %d\n", size);
      //VG_(tool_panic)("helperc_load: invalid size !");
    }
  }

  // we can depend either on the temporary number or the temporary value
  // (which is an address)
  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {
      // we don't track pointer: just load previous stored value and input
      if (VG_(strncmp)(deptmp[tmp].cons, "input", 5) != 0 && VG_(strncmp)(deptmp[tmp].cons, "ST", 2) != 0) {
        VG_(printf)("[-] Losing dependency\n");
      }
      else {
        j = add_dependency_tmp(tmp_to, deptmp[tmp].size);
        SPRINTF_CONS(deptmp[j], "LDle:%d(%s)", deptmp[tmp].size, deptmp[tmp].cons);
        ppDepTmp(&deptmp[j]);
        return;
      }
    }
  }

  del_dependency_tmp(tmp_to);
}

/////////////////////////////////

static VG_REGPARM(0) void helperc_load2(Addr addr, Tmp tmp, Tmp tmp_to, UInt size) {
  UInt a, b, c, i, j, pos;
  UInt tmp2_value;
  //tmp_to &= (0xffffffff >> (32 - size));
          //VG_(printf)("The loaded address may be %x \n", tmpto);
    //      if (depend_on_addr(tmp2_value,size)){VG_(printf)("XXXXXXXXXXXXXXXXXx");}
  //VG_(printf)("load address is %s  %08x \n", (char*) addr, addr);
  char *s = NULL ;
  char *s2 = NULL;
  s = VG_(strstr)((char*)addr,"ls");
//	  VG_(printf)("AAAAAAAAAAAAAAAAAA %s: %s %d \n", s != NULL ? "found" : "NotFound" , s , (int)(s-addr));
	//  VG_(printf)("AAAAAAAAAAAAAAAAAA %s: %08x \n", addr + (int)(s-addr), addr + (int)(s-addr));
  s2 = depend_on_addr(addr + (int)(s-addr),8);

	  //VG_(printf)("tainted address %s %8x %d\n", s2 != NULL? "Found" : "NotFound", addr + (int)(s-addr), size );
  if (addr != INVALID_ADDR) {
	  if (size == 8) {
      for (i = 0; i < depaddr8_count; i++) {
        if (depaddr8[i].value.addr != addr) continue;

        if (VG_(strncmp)(depaddr8[i].cons, "input", 5) != 0 &&
            VG_(strncmp)(depaddr8[i].cons, "ST", 2) != 0) {
          break;
        }
        j = add_dependency_tmp(tmp_to, 8);
        VG_(printf)("load address is %08x  \n", addr);
        SPRINTF_CONS(deptmp[j], "LDle:I%d(%s)", size, depaddr8[i].cons);
        ppDepTmp(&deptmp[j]);
        return;
      }

      for (i = 0; i < depaddr16_count; i++) {
        if (addr < depaddr16[i].value.addr
          || addr >= depaddr16[i].value.addr + 2)
          continue;
        pos = addr - depaddr16[i].value.addr;
        if (VG_(strncmp)(depaddr16[i].cons, "input", 5) != 0
            && VG_(strncmp)(depaddr16[i].cons, "ST", 2) != 0) {
          break;
        }
        j = add_dependency_tmp(tmp_to, 8);
        VG_(printf)("The constraint of loaded inpur is %s \n",depaddr16[i].cons);
        SPRINTF_CONS(deptmp[j],
            "32to8(And32(Shr32(8Uto32(LDle:I8(%s)),0x%x:I32),0xff:I32))",
            depaddr16[i].cons, 8 * pos);
        ppDepTmp(&deptmp[j]);
        return;
      }

      for (i = 0; i < depaddr32_count; i++) {
        if (addr < depaddr32[i].value.addr
          || addr >= depaddr32[i].value.addr + 4)
          continue;
        pos = addr - depaddr32[i].value.addr;
        if (VG_(strncmp)(depaddr32[i].cons, "input", 5) != 0
            && VG_(strncmp)(depaddr32[i].cons, "ST", 2) != 0) {
          break;
        }
        j = add_dependency_tmp(tmp_to, 8);
        VG_(printf)("The constraint of loaded inpur is %s \n",depaddr32[i].cons);
        SPRINTF_CONS(deptmp[j],
            "32to8(And32(Shr32(8Uto32(LDle:I8(%s)),0x%x:I32),0xff:I32))",
            depaddr32[i].cons, 8 * pos);
        ppDepTmp(&deptmp[j]);
        return;
      }
    }
    else if (size == 16) {
      for (i = 0; i < depaddr16_count; i++) {
        if (depaddr16[i].value.addr == addr) {
          if (VG_(strncmp)(depaddr16[i].cons, "input", 5) != 0
            && VG_(strncmp)(depaddr16[i].cons, "ST", 2) != 0) {
            break;
          }
          j = add_dependency_tmp(tmp_to, 16);
          VG_(printf)("The constraint of loaded inpur is %s \n",depaddr16[i].cons);
          SPRINTF_CONS(deptmp[j], "LDle:I%d(%s)", size, depaddr16[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }

      for (i = 0; i < depaddr32_count; i++) {
        if (addr >= depaddr32[i].value.addr && addr <= depaddr32[i].value.addr + 2) {
          pos = addr - depaddr32[i].value.addr;
          if (VG_(strncmp)(depaddr32[i].cons, "input", 5) != 0
            && VG_(strncmp)(depaddr32[i].cons, "ST", 2) != 0) {
            break;
          }
          j = add_dependency_tmp(tmp_to, 16);
          VG_(printf)("The constraint of loaded inpur is %s \n",depaddr32[i].cons);
          SPRINTF_CONS(deptmp[j], "32to16(And32(Shr32(16Uto32(LDle:I16(%s)),0x%x:I32),0xffff:I32))", depaddr32[i].cons, 8 * pos);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }

      for (i = 0; i < depaddr8_count; i++) {
        if (depaddr8[i].value.addr == addr) {
          for (a = 0; a < depaddr8_count; a++) {
            if (depaddr8[a].value.addr == addr + 1) {
              break;
            }
          }
          tl_assert(a != depaddr8_count);

          j = add_dependency_tmp(tmp_to, 16);
          VG_(printf)("load address is %08x \n", addr);

          VG_(printf)("The constraint of loaded inpur is %s \n",depaddr8[a].cons);
          SPRINTF_CONS(deptmp[j], "Cat16(LDle:I8(%s),LDle:I8(%s))", depaddr8[a].cons, depaddr8[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }
    }
    else if (size == 32) {

    	for (i = 0; i < depaddr32_count; i++) {
        if (depaddr32[i].value.addr == addr) {
          if (VG_(strncmp)(depaddr32[i].cons, "input", 5) != 0 && VG_(strncmp)(depaddr32[i].cons, "ST", 2) != 0) {
            break;
          }
          j = add_dependency_tmp(tmp_to, 32);
          VG_(printf)("load address is %08x \n", addr);

          VG_(printf)("The constraint of loaded inpur is %s \n",depaddr32[i].cons);
          SPRINTF_CONS(deptmp[j], "LDle:I32(%s)", depaddr32[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }

      }

      for (i = 0; i < depaddr8_count; i++) {
        if (depaddr8[i].value.addr == addr) {
          for (a = 0; a < depaddr8_count; a++) {
            if (depaddr8[a].value.addr == addr + 1) {
              break;
            }
          }
          for (b = 0; b < depaddr8_count; b++) {
            if (depaddr8[b].value.addr == addr + 2) {
              break;
            }
          }
          for (c = 0; c < depaddr8_count; c++) {
            if (depaddr8[c].value.addr == addr + 3) {
              break;
            }
          }
          // XXX
          //tl_assert(a != depaddr8_count && b != depaddr8_count && c != depaddr8_count);
          if (!(a != depaddr8_count && b != depaddr8_count && c != depaddr8_count)) {
            continue;
          }

          j = add_dependency_tmp(tmp_to, 32);
          VG_(printf)("The constraint of loaded inpur is %s \n",depaddr8[c].cons);

          SPRINTF_CONS(deptmp[j],
              "Cat32(LDle:I8(%s),Cat24(LDle:I8(%s),Cat16(LDle:I8(%s),LDle:I8(%s))))",
              depaddr8[c].cons,
              depaddr8[b].cons,
              depaddr8[a].cons,
              depaddr8[i].cons);
          ppDepTmp(&deptmp[j]);
          return;
        }
      }
    }
    else if (size == 64) {
      // XXX - currently not supported...
      //VG_(printf)("oops, size = 64\n");
    }
    else {
      VG_(printf)("size = %d\n", size);
      VG_(tool_panic)("helperc_load: invalid size !");
    }
  }

  // we can depend either on the temporary number or the temporary value
  // (which is an address)
  if (tmp != INVALID_TMP) {

    if (depend_of_tmp(tmp)) {

    	// we don't track pointer: just load previous stored value and input
      if (VG_(strncmp)(deptmp[tmp].cons, "input", 5) != 0 && VG_(strncmp)(deptmp[tmp].cons, "ST", 2) != 0) {
        VG_(printf)("[-] Losing dependency\n");
      }
      else {
        j = add_dependency_tmp(tmp_to, deptmp[tmp].size);
        VG_(printf)("The constraint of loaded inpur is %s \n",deptmp[tmp].cons);
        SPRINTF_CONS(deptmp[j], "LDle:%d(%s)", deptmp[tmp].size, deptmp[tmp].cons);
        ppDepTmp(&deptmp[j]);
        return;
      }
    }
  }

  del_dependency_tmp(tmp_to);
}


////////////////////////////////
static VG_REGPARM(0) void helperc_rdtmp(Tmp tmp, Tmp tmp_to) {
  UInt j;

  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {
      j = add_dependency_tmp(tmp_to, deptmp[tmp].size);
      SPRINTF_CONS(deptmp[j], "%s", deptmp[tmp].cons);
      ppDepTmp(&deptmp[j]);
      return;
    }
  }

  del_dependency_tmp(tmp_to);
}
static VG_REGPARM(0) void helperc_rdtmp2(Tmp tmp, Tmp tmp_to) {
  UInt j;

  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {
VG_(printf)("the tainted value in function for rdtmp %s \n", deptmp[tmp].cons);
      return;
    }
  }

}


static VG_REGPARM(0) void helperc_unop(Tmp tmp, Tmp tmp_to, UInt size, UInt op) {
  UInt j;
  char buffer[XXX_MAX_BUF];

  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {
      // We must use size, because some expressions change the dependency
      // size. For example: 8Uto32(a).
      j = add_dependency_tmp(tmp_to, size);
      IROp_to_str(op, buffer);
      SPRINTF_CONS(deptmp[j], "%s(%s)", buffer, deptmp[tmp].cons);
      ppDepTmp(&deptmp[j]);
      return;
    }
  }

  del_dependency_tmp(tmp_to);
}

static VG_REGPARM(0) void helperc_unop2(Tmp tmp, Tmp tmp_to, UInt size, UInt op) {
  UInt j;
  char buffer[XXX_MAX_BUF];

  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {
    	VG_(printf)("tainted value for the function unop %s \n" , deptmp[tmp].cons);
      return;
    }
  }
}
static VG_REGPARM(0) void helperc_binop(Tmp tmp1, Tmp tmp2, Tmp tmp_to, UInt op, UInt tmp1_value, UInt tmp2_value, UInt end_size) {
  UInt j1 = 0, j2 = 0;
  Bool b1 = False, b2 = False;
  char *p;
  char buffer[XXX_MAX_BUF];
  char type;
  int size;

  if (tmp1 != INVALID_TMP || tmp2 != INVALID_TMP) { 
    if (tmp1 != INVALID_TMP) {
      if (depend_of_tmp(tmp1)) {
        j1 = add_dependency_tmp(tmp_to, end_size);
        b1 = True;
      }
    }

    if (tmp2 != INVALID_TMP) {
      if (depend_of_tmp(tmp2)) {
        j2 = add_dependency_tmp(tmp_to, end_size);
        b2 = True;
      }
    }

    if (b1 || b2) {
      IROp_to_str(op, buffer);
      type = 'I';
      p = &buffer[VG_(strlen)(buffer) - 1]; // CmpEQ32
      if (*p < '0' || *p > '9') {           // CmpEQ32S
        p--;
      }

      switch (op) {
        case Iop_Shl8 ... Iop_Sar64:
          size = 8;
          break;
        default:
          switch (*p) {
            case '8': size = 8;  break;
            case '6': size = 16; break;
            case '2': size = 32; break;
            case '4': size = 64; break;
            default:
                      VG_(printf)("buffer = : %s\b", buffer);
                      VG_(tool_panic)("helperc_binop");
          }
      }

      if (b1 && b2) {
        SPRINTF_CONS(deptmp[j2], "%s(%s,%s)",
            buffer, deptmp[tmp1].cons, deptmp[tmp2].cons);
        ppDepTmp(&deptmp[j2]);
      }
      else if (b1) {
        tmp2_value &= (0xffffffff >> (32 - size));
        SPRINTF_CONS(deptmp[j1], "%s(%s,0x%x:%c%d)",
            buffer, deptmp[tmp1].cons, tmp2_value, type, size);
        ppDepTmp(&deptmp[j1]);
      }
      else if (b2) {
        tmp1_value &= (0xffffffff >> (32 - size));
        SPRINTF_CONS(deptmp[j2], "%s(0x%x:%c%d,%s)",
            buffer, tmp1_value, type, size, deptmp[tmp2].cons);
        ppDepTmp(&deptmp[j2]);
      }

      return;
    }
  }

  del_dependency_tmp(tmp_to);
}
static VG_REGPARM(0) void helperc_binop2(Tmp tmp1, Tmp tmp2, Tmp tmp_to, UInt op, UInt tmp1_value, UInt tmp2_value, UInt end_size)
{
  UInt j1 = 0, j2 = 0;
  Bool b1 = False, b2 = False;
  char *p;
  char buffer[XXX_MAX_BUF];
  char type;
  int size;

  if (tmp1 != INVALID_TMP || tmp2 != INVALID_TMP) {
    if (tmp1 != INVALID_TMP) {
      if (depend_of_tmp(tmp1)) {
        VG_(printf)("tainted value for function binop %s \n", deptmp[tmp1].cons);
      }
    }

    if (tmp2 != INVALID_TMP) {
      if (depend_of_tmp(tmp2)) {
    	  VG_(printf)("tainted value for function binop %s \n", deptmp[tmp2].cons);
      }
    }
  }
}

static VG_REGPARM(0) void helperc_mux0x(
    Tmp cond_tmp, UInt cond_value,
    Tmp expr0, Tmp exprX, Tmp tmp_to)
{
  UInt j;
  Tmp t = (cond_value) ? exprX : expr0;

  // XXX
  /*
     if (depend_of_tmp(cond_tmp)) {
     VG_(printf)("[+] 0x%08x depending of input: if (8to1(%s)) => %d\n", 0x12345678, deptmp[cond_tmp].cons, cond_value);
     }
   */

  if (t != INVALID_TMP) {
    if (depend_of_tmp(t)) {
      j = add_dependency_tmp(tmp_to, deptmp[t].size);
      SPRINTF_CONS(deptmp[j], "%s", deptmp[t].cons);
      ppDepTmp(&deptmp[j]);
      return;
    }
  }

  del_dependency_tmp(tmp_to);
}


static VG_REGPARM(0) void helperc_mux0x2(
    Tmp cond_tmp, UInt cond_value,
    Tmp expr0, Tmp exprX, Tmp tmp_to)
{
  UInt j;
  Tmp t = (cond_value) ? exprX : expr0;

  // XXX
  /*
     if (depend_of_tmp(cond_tmp)) {
     VG_(printf)("[+] 0x%08x depending of input: if (8to1(%s)) => %d\n", 0x12345678, deptmp[cond_tmp].cons, cond_value);
     }
   */

  if (t != INVALID_TMP) {
    if (depend_of_tmp(t)) {

      VG_(printf)("taint in the function mux %s",deptmp[t].cons );
      return;
    }
  }
}
static VG_REGPARM(0) void helperc_store(Addr addr, Tmp tmp,UInt tmp_value) {
  UInt j;

  //VG_(printf)("The loaded addeeeeeeee\n");

  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {
    	//for bof detection end
    		int sw1;
    		sw1=0;
    		struct Stack_Vars *cur;
    		struct Stack_Vars *search_result;
    		cur = sthead;
    		search_result=NULL;
    		int i;
    		i=0;
    		UWord maxlen;
    		//VG_(printf)("storing taint address %x \n",addr);
    		while (cur != NULL && sw1==0)
    		{
    			//VG_(printf)("the addr is %x and the  max len is %d and the result is %x and the function %s\n", cur->addr,cur->len, cur->addr+cur->len, cur->fn_name);
    			if (addr >= cur-> addr && addr<= (cur->addr + cur->maxlen))
    			{
        		  //  VG_(printf)("the addr is %x and the  max len is %d and the result is %x \n", cur->addr,cur->maxlen, cur->addr+cur->maxlen);
    //				VG_(printf)("bof len is %d and const is %s for address 0x%x  and function %s\n", cur->len, depend_on_addr(cur->addr,8), cur->addr, cur->fn_name);
    				search_result=cur;
    				sw1=1;
    				i=i+1;
    			}
    			cur = cur->next;
    		}
    		if (search_result!=NULL)
    		{
    			VG_(printf)("address=> 0x%x @@@ const => (%s) @@@ len => (%d) @@@ fnname => (%s) @@@ infn => (%s)\n",search_result->addr, deptmp[tmp].cons,search_result->maxlen, search_result->fn_name, func_name);
    		}

    	//for bof detection
      if (deptmp[tmp].size == 32) {
        // XXX - we're asserting that values don't overlap
        // add dependency to the 32 bit value
        j = add_dependency_addr(addr, 32);
        SPRINTF_CONS(depaddr32[j], "STle(%s)", deptmp[tmp].cons);
        ppDepAddr(&depaddr32[j]);


        // delete any dependency stored at this address
        for (j = 0; j < depaddr16_count; j++) {
          if (depaddr16[j].value.addr >= addr && depaddr16[j].value.addr <= addr + 2) {
            del_dependency_addr(depaddr16[j].value.addr, 16);
          }
        }

        for (j = 0; j < depaddr8_count; j++) {
          if (depaddr8[j].value.addr >= addr && depaddr8[j].value.addr < addr + 4) {
            del_dependency_addr(depaddr8[j].value.addr, 8);
          }
        }
      }
      else if (deptmp[tmp].size == 16) {
        j = add_dependency_addr(addr, 16);
        SPRINTF_CONS(depaddr16[j], "STle(%s)", deptmp[tmp].cons);
        ppDepAddr(&depaddr16[j]);

        for (j = 0; j < depaddr8_count; j++) {
          if (depaddr8[j].value.addr >= addr && depaddr8[j].value.addr < addr + 2) {
            del_dependency_addr(depaddr8[j].value.addr, 8);
          }
        }
      }

      else if (deptmp[tmp].size == 8) {
        // add dependency to the 8 bit value
        j = add_dependency_addr(addr, 8);
        SPRINTF_CONS(depaddr8[j], "STle(%s)", deptmp[tmp].cons);
        ppDepAddr(&depaddr8[j]);

        // if it overwrite a 32 or 16 bits value, fragment them
      }
      else {
        VG_(printf)("deptmp[%d].size = %d\n", tmp, deptmp[tmp].size);
        VG_(printf)("deptmp[%d].cons = %s", tmp, deptmp[tmp].cons);
        VG_(tool_panic)("helperc_store: dependency size not handled");
      }
      return;
    }
  }

  // XXX !
  del_dependency_addr(addr, 32);
  del_dependency_addr(addr, 16);
  del_dependency_addr(addr, 8);
}
static VG_REGPARM(0) void helperc_regebp( Int length, Tmp tmp,UInt tmp_value) {
int size;
	size=32;
	Addr add;
	  if (tmp_value){
	  tmp_value&= (0xffffffff >> (32 - size));
	  add=(UWord) tmp_value;
	  ebp=add;
	 if (length <=0)
		  {
					  AddStack(add+length, length, 0);
					  //VG_(printf)("add the address is %x the len is %d \n", add+length,length);
		  }
		  else
		  {
						  AddStack(add, length, 0);
						//  VG_(printf)("add the address is %x the len is %d \n", add,length);
		  }

	        		  	  }
}
static VG_REGPARM(0) void helperc_regebp2( Int length, Tmp tmp,UInt tmp_value) {
int size;
	size=32;
	Addr add;
	  if (tmp_value){
	  tmp_value&= (0xffffffff >> (32 - size));
	  add=(UWord) tmp_value;
	  	  	  ebp=add;
	          AddStack(add-length, length, 0);
	          //VG_(printf)("sub the address is %x the len is %d \n", add-length,length);


	        		  	  }
}

static VG_REGPARM(0) void helperc_regebp3( Int length, Tmp tmp,UInt tmp_value) {
int size;
	size=32;
	Addr add;
	  if (tmp_value){
	  tmp_value&= (0xffffffff >> (32 - size));
	  add=(UWord) tmp_value;
	  if (length <=0)
	  {
	  	          AddStack(add+length, length, 0);
	  	        //VG_(printf)("add the address is %x the len is %d \n", add+length,length);
	  }
	  else
	  {
	  	  	          AddStack(add, length, 0);
	  	  	      //VG_(printf)("add the address is %x the len is %d \n", add,length);
	  }


	  }
}

static VG_REGPARM(0) void helperc_regebp4( Int length, Tmp tmp,UInt tmp_value) {
int size;
	size=32;
	Addr add;
	  if (tmp_value){
	  tmp_value&= (0xffffffff >> (32 - size));
	  add=(UWord) tmp_value;
	          AddStack(add-length, length, 0);
	          //VG_(printf)("sub the address is %x the len is %d \n", add-length,length);

	        		  	  }
}

static VG_REGPARM(0) void helperc_regebp5( UInt length, Tmp tmp,UInt tmp_value) {
int size;
	size=32;
	Addr add;
	  if (tmp_value){
	  tmp_value&= (0xffffffff >> (32 - size));
	  length&= (0xffffffff >> (32 - size));
	  add=(UWord) tmp_value;
	  if (length <=0)
	  	  {
	  	  	          AddStack(add+length, length, 0);
	  	  	    //      VG_(printf)("add the address is %x the len is %d \n", add+length,length);
	  	  }
	  	  else
	  	  {
	  	  	  	          AddStack(add, length, 0);
	  	  	  	  //        VG_(printf)("add the address is %x the len is %d \n", add,length);
	  	  }


	         }
}


static VG_REGPARM(0) void helperc_regebp6( UInt length, Tmp tmp,UInt tmp_value) {
int size;
	size=32;
	Addr add;
	  if (tmp_value){
	  tmp_value&= (0xffffffff >> (32 - size));
	  length&= (0xffffffff >> (32 - size));
	  add=(UWord) tmp_value;
	  	  	          AddStack(add-length, length, 0);
	  	  	    //      VG_(printf)("add the address is %x the len is %d \n", add+length,length);
	         }
}



static VG_REGPARM(0) void helperc_store2(Addr addr, Tmp tmp,UInt tmp_value) {
  UInt j;
Addr add2;
  //VG_(printf)("The loaded addeeeeeeee\n");
  int size;
  int cnt;
  cnt=1;

  size=32;
  if (tmp_value){
  tmp_value&= (0xffffffff >> (32 - size));
          //VG_(printf)("The stored address may be %x \n", tmp_value);
          if (depend_on_addr((UWord)(tmp_value),8))        {
        	  add2=(UWord)(tmp_value);
        	  //VG_(printf)("add2 is %x \n", add2);

        	  VG_(printf)("const is %s \n", depend_on_addr((UWord)(tmp_value),8));
          }
          while(cnt<100){
        	  if (depend_on_addr((UWord)(tmp_value)+cnt,8))        {
        	          	  add2=(UWord)(tmp_value);
        	          	  //VG_(printf)("add2 is %x \n", add2);

        	          	  VG_(printf)("const is %s \n", depend_on_addr((UWord)(tmp_value)+cnt,8));
          }
          	  cnt=cnt+1;

  }

  }
  if (tmp != INVALID_TMP) {
    if (depend_of_tmp(tmp)) {

      if (deptmp[tmp].size == 32) {
        // XXX - we're asserting that values don't overlap
        // add dependency to the 32 bit value
        j = add_dependency_addr(addr, 32);
        VG_(printf)("The constraint of stored inpur is %s \n",deptmp[tmp].cons);

        SPRINTF_CONS(depaddr32[j], "STle(%s)", deptmp[tmp].cons);
        ppDepAddr(&depaddr32[j]);


        // delete any dependency stored at this address
        for (j = 0; j < depaddr16_count; j++) {
          if (depaddr16[j].value.addr >= addr && depaddr16[j].value.addr <= addr + 2) {
            del_dependency_addr(depaddr16[j].value.addr, 16);
          }
        }

        for (j = 0; j < depaddr8_count; j++) {
          if (depaddr8[j].value.addr >= addr && depaddr8[j].value.addr < addr + 4) {
            del_dependency_addr(depaddr8[j].value.addr, 8);
          }
        }
      }
      else if (deptmp[tmp].size == 16) {
        j = add_dependency_addr(addr, 16);
        VG_(printf)("The constraint of stored inpur is %s \n",deptmp[tmp].cons);

        SPRINTF_CONS(depaddr16[j], "STle(%s)", deptmp[tmp].cons);
        ppDepAddr(&depaddr16[j]);

        for (j = 0; j < depaddr8_count; j++) {
          if (depaddr8[j].value.addr >= addr && depaddr8[j].value.addr < addr + 2) {
            del_dependency_addr(depaddr8[j].value.addr, 8);
          }
        }
      }

      else if (deptmp[tmp].size == 8) {
        // add dependency to the 8 bit value
        j = add_dependency_addr(addr, 8);
        SPRINTF_CONS(depaddr8[j], "STle(%s)", deptmp[tmp].cons);
        VG_(printf)("The constraint of stored inpur is %s \n",deptmp[tmp].cons);

        ppDepAddr(&depaddr8[j]);

        // if it overwrite a 32 or 16 bits value, fragment them
      }
      else {
        VG_(printf)("deptmp[%d].size = %d\n", tmp, deptmp[tmp].size);
        VG_(printf)("deptmp[%d].cons = %s", tmp, deptmp[tmp].cons);
        VG_(tool_panic)("helperc_store: dependency size not handled");
      }
      return;
    }
  }

  // XXX !
  del_dependency_addr(addr, 32);
  del_dependency_addr(addr, 16);
  del_dependency_addr(addr, 8);
}


static VG_REGPARM(0) void helperc_exit(Tmp guard, Addr addr, UInt taken) {
	//VG_(printf)("exit \n");

	if (depend_of_tmp(guard)) {
    VG_(printf)("\n[+] 0x%08x depending on input: if (%s) => %d\n",
        (UInt)addr, deptmp[guard].cons, taken);

    return;
  }
}

static VG_REGPARM(0) void helperc_intconvnot32( Tmp arg,UInt end_size)
{
  if (depend_of_tmp(arg)) {
	  VG_(printf)("[+] 0x1212 int overflow: if (32to1(1Uto32(CmpNE32(%s,0x80000000:I32)))) \n", deptmp[arg].cons);
  }
}
static VG_REGPARM(0) void helperc_intconv( Tmp arg,UInt end_size)
{
  if (depend_of_tmp(arg)) {
	  VG_(printf)("[+] 0x1010 int overflow: if (32to1(1Uto32(CmpLT32U(%s,0x000000ff:I32)))) \n", deptmp[arg].cons);
  }
}
static VG_REGPARM(0) void helperc_intconv32to16( Tmp arg,UInt end_size)
{
  if (depend_of_tmp(arg)) {
	  VG_(printf)("[+] 0x9111 int overflow: if (32to1(1Uto32(CmpLT32U(%s,0x0000ffff:I32)))) \n", deptmp[arg].cons);
  }
}
static VG_REGPARM(0) void helperc_intget(Reg offset, Tmp tmp, UInt size) {
  UInt j;

  if (depend_of_reg(offset)) {
	  if(size==8){
		  VG_(printf)("[+] 0x999 int overflow: if (32to1(1Uto32(CmpLT32U(0x000000ff:I32,GET:I32(%s))))) \n", depreg[offset].cons);
		  return;
	  }
	  if(size==16){
	  		  VG_(printf)("[+] 0x999 int overflow: if (32to1(1Uto32(CmpLT32U(GET:I32(%s),0x0000ffff:I32)))) \n", depreg[offset].cons);
	  		  return;
	  	  }

  }
}
static VG_REGPARM(0) void helperc_intarth(Tmp tmp1, Tmp tmp2, Tmp tmp_to, UInt op, UInt tmp1_value, UInt tmp2_value, UInt opnum)
{


  UInt j1 = 0, j2 = 0;
  Bool b1 = False, b2 = False;
  char *p;
//  char buffer[XXX_MAX_BUF];
  char type;
  int size=32;
  char* value, value2;
  value="0x7fffffff:I32";

 int opsize;

  type='I';
  if (tmp1 != INVALID_TMP || tmp2 != INVALID_TMP) {

    if (tmp1 != INVALID_TMP) {
      if (depend_of_tmp(tmp1)) {
      b1 = True;
      switch(deptmp[tmp1].size){
      case 1: {value= "0xfe:I8"; opsize=8; break;}
      case 8:  {value= "0x00ff:I16"; opsize=16; break;}
      case 16:{value= "0x0000ffff:I32";opsize=32; break;}
      case 32:{value= "0x00000000ffffffff:I64"; opsize=64; break;}
      case 64:{value= "0xffffffffffff:I64"; opsize=64; break;} //To-Decided upon

      }
      //  VG_(printf)("ok1");
      }
    }


    if (tmp2 != INVALID_TMP) {
      if (depend_of_tmp(tmp2)) {
        b2 = True;
        switch(deptmp[tmp2].size){
			case 1: {value= "0xfe:I8"; opsize=8; break;}
			case 8:  {value= "0x00ff:I16"; opsize=16; break;}
			case 16:{value= "0x0000ffff:I32";opsize=32; break;}
			case 32:{value= "0x00000000ffffffff:I64"; opsize=64; break;}
			case 64:{value= "0xffffffffffff:I64"; opsize=64; break;} //To-Decided upon

        }    // VG_(printf)("ok2");
      }
    }

    //unsigned mul32 int overflow:
    if (opnum==14  ){
    	value="0x00000000ffffffff:I64";
    	if (b1 && b2) {
      	  VG_(printf)("[+] 0x141 int overflow: if (32to1(1Uto32(CmpLT64U(%s,MullU64(32Uto64(%s),32Uto64(%s)))))) \n",value,deptmp[tmp1].cons,deptmp[tmp2].cons);

    	        }
    	        else if (b1) {
    	          tmp2_value &= (0xffffffff >> (32 - size));

    	        	  VG_(printf)("[+] 0x141 int overflow: if (32to1(1Uto32(CmpLT64U(%s,MullU64(32Uto64(%s),32Uto64(0x%x:I32)))))) \n",value,deptmp[tmp1].cons, tmp2_value);
    	      	        }
    	        else if (b2) {
    	          tmp1_value &= (0xffffffff >> (32 - size));

	        	  VG_(printf)("[+] 0x141 int overflow: if (32to1(1Uto32(CmpLT64U(%s,MullU64(32Uto64(%s),32Uto64(0x%x:I32)))))) \n",value,deptmp[tmp2].cons, tmp1_value);
    	        }
    	//return;
    }

    //subtract int overflow
    if (opnum==9){

    	value="0x80000000:I32";
    	if (b1 && b2) {
            //tmp1>0
    		VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
    		//tmp2<0
    		VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp2].cons);
      	  //x1-x2 , x1>0 and x2<0 int overflow
    		VG_(printf)("[+] 0x1919 int overflow: if (32to1(1Uto32(CmpLT32U(0x7fffffff:I32,Sub32(%s,%s))))) \n",deptmp[tmp1].cons, deptmp[tmp2].cons);

    		 //x1-x2 , x1<0 and x2>0 int underflow
    		//tmp2>0
    		VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp2].cons);
    		//tmp1<0
    		VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
      	  //x1-x2 , x1>0 and x2<0 int overflow
    		 VG_(printf)("[+] 0x1919 int overflow: if (32to1(1Uto32(CmpLT32U(Sub32(%s,%s),%s)))) \n",deptmp[tmp1].cons,deptmp[tmp2].cons,value);

    	        }
    	        else if (b1) {
    	          tmp2_value &= (0xffffffff >> (32 - size));
    	          if(tmp2_value>0){
    	              VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);

    	        	  VG_(printf)("[+] 0x1919 int overflow: if (32to1(1Uto32(CmpLT32U(Sub32(%s,0x%x:I32),%s)))) \n",deptmp[tmp1].cons, tmp2_value,value);
    	          }
    	          if(tmp2_value<0){

    	        	  VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);

    	        	  VG_(printf)("[+] 0x1919 int overflow: if (32to1(1Uto32(CmpLT32U(0x7fffffff:I32,Sub32(%s,0x%x:I32))))) \n",deptmp[tmp1].cons, tmp2_value);
    	          }																																																																																																																																																																																																									

    	        }
    	        else if (b2) {
    	          tmp1_value &= (0xffffffff >> (32 - size));
    	          if(tmp1_value>0){
    	              //tmp1-x, x<0 int overflow=> tmp2<0
    	        	  VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp2].cons);
      	        	  VG_(printf)("[+] 0x1919 int overflow: if (32to1(1Uto32(CmpLT32U(0x7fffffff:I32,Sub32(0x%x:I32,%s))))) \n", tmp1_value,deptmp[tmp2].cons);

    	             }
																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																			
    	          if(tmp1_value<0){
    	        	  //tmp1-x,x>0 int underflow
    	              VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp2].cons);
    	              VG_(printf)("[+] 0x1919 int overflow: if (32to1(1Uto32(CmpLT32U(Sub32(0x%x:I32,%s),%s)))) \n", tmp1_value,deptmp[tmp2].cons,value);
    	              	          }
    	        }
    	return;
    }
  //signed multilply
    if (opnum==8){
        if (b1 && b2) {
        	//tmp1>0 and tmp2>0
            VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
            VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp2].cons);
            value="0x000000007fffffff:I64";
            VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,Mul64(32Sto64(%s),32Sto64(%s)))))) \n",value,deptmp[tmp1].cons,deptmp[tmp2].cons);

            // for a negative result and underflow to positive
            //tmp1<0 and tmp2<0
            VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
            VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp2].cons);
            value="0x8000000000000000:I64";
            VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Mul64(32Sto64(%s),32Sto64(%s))),%s))) \n",deptmp[tmp1].cons,deptmp[tmp2].cons,value);

        }
        else if (b1) {
          tmp2_value &= (0xffffffff >> (32 - size));
          if (tmp2_value>0){
              VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32U(0x7fffffff:I32,%s)))) => 1\n",deptmp[tmp1].cons);
              value="0x80000000:I32";

             VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT32U(Mul32(%s,0x%x:I32),%s)))) \n",deptmp[tmp1].cons, tmp2_value,value);

        	  VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32U(%s,0x80000000:I32)))) => 1\n",deptmp[tmp1].cons);
             value="0x7fffffff:I32";

            VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT32U(%s,Mul32(%s,0x%x:I32))))) \n",value,deptmp[tmp1].cons, tmp2_value);

             // for a negative result and underflow to positive

          }
          if (tmp2_value<0){
              VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
              value="0x000000007fffffff:I64";

             VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,(Mul64(32Sto64(%s),32Sto64(0x%x:I32))))))) \n",value,deptmp[tmp1].cons, tmp2_value);

              // for a negative result and underflow
              VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
              value="0x8000000000000000:I64";

             VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Mul64(32Sto64(%s),32Sto64(0x%x:I32))),%s)))) \n",deptmp[tmp1].cons, tmp2_value,value);

          }
        }

        else if (b2) {
          tmp1_value &= (0xffffffff >> (32 - size));

          if (tmp1_value>0){
             VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp2].cons);
             value="0x000000007fffffff:I64";

            VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,Mul64(32Sto64(%s),32Sto64(0x%x:I32)))))) \n",value,deptmp[tmp2].cons, tmp1_value);

             // for a negative result and underflow to positive
             VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp2].cons);
             value="0x8000000000000000:I64";

            VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Mul64(32Sto64(%s),32Sto64(0x%x:I32)),%s)))) \n",deptmp[tmp2].cons, tmp1_value,value);

          }
          if (tmp2_value<0){
              VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
              value="0x000000007fffffff:I64";

             VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,Mul64(32Sto64(%s),32Sto64(0x%x:I32)))))) \n",value,deptmp[tmp1].cons, tmp2_value);

              // for a negative result and underflow
              VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
              value="0x8000000000000000:I64";

             VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Mul32(32Sto64(%s),32Sto64(0x%x:I32)),%s)))) \n",deptmp[tmp1].cons, tmp2_value,value);

          }
        }
        return;

    }
///////////////////////////shl32

        if (opnum==16){
        	//return;
           if (b1 && b2) {
            	//tmp1>0 and tmp2>0
                VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
                VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp2].cons);
                value="0x000000007fffffff:I64";
                VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,Shl64(32Sto64(%s),32Sto64(%s)))))) \n",value,deptmp[tmp1].cons,deptmp[tmp2].cons);

                // for a negative result and underflow to positive
                //tmp1<0 and tmp2<0
                VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
                VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp2].cons);
                value="0x8000000000000000:I64";
                VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Shl64(32Sto64(%s),32Sto64(%s))),%s))) \n",deptmp[tmp1].cons,deptmp[tmp2].cons,value);

            }
            else if (b1) {
              tmp2_value &= (0xffffffff >> (32 - size));
              if (tmp2_value>0){
                 VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
                 value="0x000000007fffffff:I64";

                VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,Shl64(32Sto64(%s),32Sto64(0x%x:I32)))))) \n",value,deptmp[tmp1].cons, tmp2_value);

                 // for a negative result and underflow to positive
                 VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
                 value="0x8000000000000000:I64";

                VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Shl64(32Sto64(%s),32Sto64(0x%x:I32)),%s)))) \n",deptmp[tmp1].cons, tmp2_value,value);

              }
              if (tmp2_value<0){
                  VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
                  value="0x000000007fffffff:I64";

                 VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,(Shl64(32Sto64(%s),32Sto64(0x%x:I32))))))) \n",value,deptmp[tmp1].cons, tmp2_value);

                  // for a negative result and underflow
                  VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
                  value="0x8000000000000000:I64";

                 VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Shl64(32Sto64(%s),32Sto64(0x%x:I32))),%s)))) \n",deptmp[tmp1].cons, tmp2_value,value);

              }
            }

            else if (b2) {
              tmp1_value &= (0xffffffff >> (32 - size));

              if (tmp1_value>0){
                 VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp2].cons);
                 value="0x000000007fffffff:I64";

                VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,Mul64(32Sto64(%s),32Sto64(0x%x:I32)))))) \n",value,deptmp[tmp2].cons, tmp1_value);

                 // for a negative result and underflow to positive
                 VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp2].cons);
                 value="0x8000000000000000:I64";

                VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Mul64(32Sto64(%s),32Sto64(0x%x:I32)),%s)))) \n",deptmp[tmp2].cons, tmp1_value,value);

              }
              if (tmp2_value<0){
                  VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
                  value="0x000000007fffffff:I64";

                 VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(%s,Mul64(32Sto64(%s),32Sto64(0x%x:I32)))))) \n",value,deptmp[tmp1].cons, tmp2_value);

                  // for a negative result and underflow
                  VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
                  value="0x8000000000000000:I64";

                 VG_(printf)("[+] 0x888 int overflow: if (32to1(1Uto32(CmpLT64U(Mul32(32Sto64(%s),32Sto64(0x%x:I32)),%s)))) \n",deptmp[tmp1].cons, tmp2_value,value);

              }
            }
            return;

        }

///////////////////////////shl32


    //setting the size for unsigned add int overflow
    char *unvalue;
    switch(opnum){
        case 4:
       	 size=8; unvalue="0x00ff:I16"; break;
        case 5:
       	 size=16; unvalue="0x0000ffff:I32"; break;
        case 6:
       	 size=32; unvalue="0x00000000ffffffff:I64"; break;
        case 8:
         size=64; unvalue="0xfffffffffffffff:I64"; break;// to decide upon
        default:
        	unvalue="0x00000000ffffffff:I64"; break;
        }

      if (b1 && b2) {
     	    //unsigned int overflow
//          VG_(printf)("[+] 0x6666 int overflow: if (32to1(1Uto32(CmpLT%dU(%s,Add%d(%dUto%d(%s),%dUto%d(%s)))))) \n", size*2,unvalue,size*2,size,size*2,deptmp[tmp1].cons,size,size*2,deptmp[tmp2].cons );
//incomplete

      }
      else if (b1) {
        tmp2_value &= (0xffffffff >> (32 - size));
        //unsigned int overfow
        VG_(printf)("[+] 0x6666 int overflow: if (32to1(1Uto32(CmpLT%dU(%s,Add%d(%dUto%d(%s),%dUto%d(0x%x:I%d)))))) \n", size*2,unvalue,size*2,size,size*2,deptmp[tmp1].cons,size,size*2,tmp2_value,size );
        if (tmp2_value>0){
        	value="0x7fffffff:I32";
        VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp1].cons);
        VG_(printf)("[+] 0x4568 int overflow: if (32to1(1Uto32(CmpLT32U(%s,Add32(%s,0x%x:I32))))) \n", value,deptmp[tmp1].cons, tmp2_value);
        }
        if (tmp2_value<0){
        		value="0x80000000:I32";
        	    VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp1].cons);
                VG_(printf)("[+] 0x4568 int overflow: if (32to1(1Uto32(CmpLT32U(Add32(%s,0x%x:I32),%s)))) \n",deptmp[tmp1].cons, tmp2_value, value);
                }
      }
      else if (b2) {
        tmp1_value &= (0xffffffff >> (32 - size));
        VG_(printf)("[+] 0x6666 int overflow: if (32to1(1Uto32(CmpLT%dU(%s,Add%d(%dUto%d(%s),%dUto%d(0x%x:I%d)))))) \n", size*2,unvalue,size*2,size,size*2,deptmp[tmp2].cons,size,size*2,tmp1_value,size );
        if (tmp1_value>0){
                	value="0x7fffffff:I32";
                VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(0x00:I32,%s)))) => 1\n",deptmp[tmp2].cons);
                VG_(printf)("[+] 0x4568 int overflow: if (32to1(1Uto32(CmpLT32U(%s,Add32(%s,0x%x:I32))))) \n", value,deptmp[tmp2].cons, tmp1_value);
                }
		if (tmp1_value<0){
				value="0x80000000:I32";
				VG_(printf)("[+] 0x011111 depending on input: if (32to1(1Uto32(CmpLT32S(%s,0x00:I32)))) => 1\n",deptmp[tmp2].cons);
				VG_(printf)("[+] 0x4568 int overflow: if (32to1(1Uto32(CmpLT32U(Add32(%s,0x%x:I32),%s)))) \n",deptmp[tmp2].cons, tmp1_value, value);
				}
      } 
      return;
}

}


static VG_REGPARM(0) void helperc_null( Tmp arg2, Tmp arg1)
{
  if (depend_of_tmp(arg2)) {
	  char* s, type;
	  int size;

	  //VG_(printf)("load taint constraint %s", deptmp[arg2].cons);
	  switch (deptmp[arg2].size)
	  	    {
	  	      case 1:  {s= "0x0:I1";     type="1";   size=1;         break;}
	  	      case 8:  {s= "0x00:I8";     type="8";  size=8;         break;}
	  	      case 16: {s= "0x00:I16";     type="16";      size=16;  break;}
	  	      case 32: {s="0x00:I32";     type="32";    size=32;  break;}
	  	      case 64: {s= "0x00:I64"; type="64";  size=64; break;}
	  	      default: break;
	  	      	    }

	  //in the future compare operator should be defined based on type

	  VG_(printf)("[+] 0x321 null pointer reference: if (32to1(1Uto32(CmpEQ%d(%s,%s)))) \n", size, deptmp[arg2].cons, s);
  }
}
static VG_REGPARM(0) void helperc_null2(Tmp arg2, Tmp arg1) {
  if (depend_of_tmp(arg2)) {
	  char* s, type;
	  switch (deptmp[arg2].size)
	  	    {
	  	      case 1:  {s= "0x0:I1";     type="1";            break;}
	  	      case 8:  {s= "0x00:I8";     type="8";           break;}
	  	      case 16: {s= "0x00:I16";     type="16";        break;}
	  	      case 32: {s="0x00:I32";     type="32";      break;}
	  	      case 64: {s= "0x00:I64"; type="64";  break;}
	  	      default: break;
	  	      	    }

	  //in the future compare operator should be defined based on type
	  VG_(printf)("[+] 0x321 null pointer reference: if (32to1(1Uto32(CmpEQ32(%s,%s)))) \n", deptmp[arg2].cons,s);

  }
}

static VG_REGPARM(0) void helperc_div(Tmp arg2, Tmp arg1) {
//VG_(printf)("divisor tmp index is %d \n",arg2);
	if (depend_of_tmp(arg2)) {
	  int v=0;
	  char* s;
	  switch (deptmp[arg2].size)
	    {
	      case 1:  s= "1";                 break;
	      case 8:  s= "8";                break;
	      case 16: s= "16";             break;
	      case 32: s="32";           break;
	      case 64: s= "64";  break;
	      default: break;
	      	    }
	  //VG_(printf)("@@@@@@@@%s=%s@@@@@@@@@", deptmp[arg2], s);
	 VG_(printf)("[+] 0x123 division by zero: if (32to1(1Uto32(CmpEQ%s(%s,0x00:I%s)))) \n", s,deptmp[arg2].cons, s);
    return;
  }
}


static VG_REGPARM(0) void helperc_x86g_calculate_condition(
    Tmp tmp_to,
    UInt cond, UInt cc_op,
    Tmp cc_dep1, Tmp cc_dep2,
    UInt cc_dep1_value, UInt cc_dep2_value)
{

  UInt j1 = 0, j2 = 0;
  Bool b1 = False, b2 = False;
  char type = 'I';
  int size = 32;

  if (depend_of_tmp(cc_dep1)) {
    j1 = add_dependency_tmp(tmp_to, deptmp[cc_dep1].size);
    b1 = True;
  }

  if (depend_of_tmp(cc_dep2)) {
    j2 = add_dependency_tmp(tmp_to, deptmp[cc_dep2].size);
    b2 = True;
  }

  if (b1 || b2) {        
    if (b1 && b2) {
      SPRINTF_CONS(deptmp[j2],
          "x86g_calculate_condition(0x%x:I32,0x%x:I32,%s,%s)",
          cond, cc_op, deptmp[cc_dep1].cons, deptmp[cc_dep2].cons);
      ppDepTmp(&deptmp[j2]);
    }
    else if (b1) {
      SPRINTF_CONS(deptmp[j1],
          "x86g_calculate_condition(0x%x:I32,0x%x:I32,%s,0x%x:%c%d)",
          cond, cc_op, deptmp[cc_dep1].cons, cc_dep2_value, type, size);
      ppDepTmp(&deptmp[j1]);
    }
    else if (b2) {
      SPRINTF_CONS(deptmp[j2],
          "x86g_calculate_condition(0x%x:I32,0x%x:I32,0x%x:%c%d,%s)",
          cond, cc_op, cc_dep1_value, type, size, deptmp[cc_dep2].cons);
      ppDepTmp(&deptmp[j2]);
    }

    return;
  } 

  del_dependency_tmp(tmp_to);
}

#define Not_Important 20000

static Bool CompareExpr(IRExpr* cmd, IRExpr* cont)
{
	if (cmd->tag != cont->tag)
		return False;


	switch (cmd->tag)
	{
	case Iex_Get:
		return True;

		break;
	case Iex_Load:
		if ((cont->Iex.Load.addr==NULL || CompareExpr(cont->Iex.Load.addr, cmd->Iex.Load.addr)) &&
				(cont->Iex.Load.end==Not_Important || cont->Iex.Load.end== cmd->Iex.Load.end) &&
				(cont->Iex.Load.ty=Not_Important || cont->Iex.Load.ty== cmd->Iex.Load.ty))
			   return True;

		break;
	case Iex_Unop:
		break;
	case Iex_Binop:
		//VG_(printf)("op:%d\n" , cmd->Iex.Binop.op );

		//VG_(printf)("arg1_Equality:%d\n", cont->Iex.Binop.arg1 == NULL ? 0 : -1);
		//VG_(printf)(" arg2_Equality:%d\n", CompareExpr(cmd->Iex.Binop.arg2 ,cont->Iex.Binop.arg2)== True ? 1 : 0);
		//VG_(printf)(IRExpr_RdTmp(cmd->Iex.Binop.arg1->Iex.RdTmp.tmp));
		if ((cont->Iex.Binop.op != Not_Important && cont->Iex.Binop.op == cmd->Iex.Binop.op) &&
			(cont->Iex.Binop.arg1 == NULL || CompareExpr(cmd->Iex.Binop.arg1 ,cont->Iex.Binop.arg1) == True)&&
			(cont->Iex.Binop.arg2 == NULL || CompareExpr(cmd->Iex.Binop.arg2 ,cont->Iex.Binop.arg2) == True))
			//{VG_(printf)("EXP matched");
			return True;
		else
			return False;
		break;
	case Iex_Triop:
		break;
	case Iex_Qop:
		break;
	default:
		break;
	}
	return False;

}
static Bool CompareStmt(IRStmt* cmd, IRStmt* cont)
{
	   //ppIStmt(cmd);
		// VG_(printf)("\n");

	if (cmd->tag != cont->tag)
		return False;

	switch (cmd->tag)
	{
	case Ist_Put:
		if (cont->Ist.Put.data != NULL &&
				CompareExpr(cmd->Ist.Put.data , cont->Ist.Put.data) == True)
		{//VG_(printf)("container found\n");
				return True;
		}
		break;
   case Ist_WrTmp:
	   if (cont->Ist.WrTmp.data != NULL &&
	   				CompareExpr(cmd->Ist.WrTmp.data , cont->Ist.WrTmp.data) == True)
	   			{//VG_(printf)("container found\n");
	   			return True;}
	 break;
   case Ist_Store:
	   if ((cont->Ist.Store.addr== NULL || CompareExpr(cmd->Ist.Store.addr, cont->Ist.Store.addr)==True) &&
			(cont->Ist.Store.data==NULL || CompareExpr(cmd->Ist.Store.data, cont->Ist.Store.data)==True) &&
			(cont->Ist.Store.end== Not_Important || cont->Ist.Store.end==cmd->Ist.Store.end ))
			   {
		   return True;
	   }

	 break;
   case Ist_Exit:
	 break;
   default: break;

	}
	   return False;

}
/*
typedef struct _BB          BB;
typedef struct _obj_node    obj_node;


Addr bb_addr(BB* bb)  {
	VG_(printf)("the address is found");
	return bb->offset + bb->obj->offset;
}*/
Bool get_debug_info(Addr instr_addr, Char file[100], Char fn_name[100], UInt* line_num, DebugInfo** pDebugInfo)
{

  Bool found_file_line, found_fn, found_dirname, result = True;
  Char dir[100];
  UInt line;

  //CLG_DEBUG(6, "  + get_debug_info(%#lx)\n", instr_addr);

  if (pDebugInfo) {
      *pDebugInfo = VG_(find_DebugInfo)(instr_addr);

      // for generated code in anonymous space, pSegInfo is 0
   }

   found_file_line = VG_(get_filename_linenum)(instr_addr,
					       file, 100,
					       dir, 100,
					       &found_dirname,
					       &line);
   found_fn = VG_(get_fnname)(instr_addr,
			      fn_name, 100);

   if (found_dirname) {
       // +1 for the '/'.
       //ASSERT(VG_(strlen)(dir) + VG_(strlen)(file) + 1 < 100);
       VG_(strcat)(dir, "/");         // Append '/'
       VG_(strcat)(dir, file);    // Append file to dir
       VG_(strcpy)(file, dir);    // Move dir+file to file
   }

   if (!found_file_line && !found_fn) {
     //CLG_(stat).no_debug_BBs++;
     VG_(strcpy)(file, "???");
     VG_(strcpy)(fn_name,  "???");
     if (line_num) *line_num=0;
     result = False;

   } else if ( found_file_line &&  found_fn) {
    // CLG_(stat).full_debug_BBs++;
     if (line_num) *line_num=line;

   } else if ( found_file_line && !found_fn) {
     //CLG_(stat).file_line_debug_BBs++;
     VG_(strcpy)(fn_name,  "???");
     if (line_num) *line_num=line;

   } else  /*(!found_file_line &&  found_fn)*/ {
     //CLG_(stat).fn_name_debug_BBs++;
     VG_(strcpy)(file, "???");
     if (line_num) *line_num=0;
   }

   /*CLG_DEBUG(6, "  - get_debug_info(%#lx): seg '%s', fn %s\n",
	    instr_addr,
	    !pDebugInfo   ? (const UChar*)"-" :
	    (*pDebugInfo) ? VG_(DebugInfo_get_filename)(*pDebugInfo) :(const UChar*)"(None)",
	    fn_name);
*/
  return result;
}






static int checkfunctionname(Addr bb){
	Char filename[100], fnname[100];
	    DebugInfo* di;
	    UInt       line_num;
	    /* fn from debug info is idempotent for a BB */

	    //if (bb->fn){ VG_(printf)("this is the function %s", bb->fn);}

	   //CLG_DEBUG(3,"+ get_fn_node(BB %#lx)\n", bb_addr(bb));

	    /* get function/file name, line number and object of
	     * the BB according to debug information
	     */
	    get_debug_info(bb,filename, fnname, &line_num, &di);
	    //VG_(printf)("this is a memcpy function %s\n", fnname);
	  //VG_(printf)(" function %s\n\n\n", fnname);
//for bof detection
	    if (fnname){
	    VG_(strcpy)(func_name,fnname);
		//VG_(printf)("this is a bad function %s\n", func_name);
	    if (0 == VG_(strcmp)(fnname, "system") || 0 == VG_(strcmp)(fnname, "mysql_query")|| 0 == VG_(strcmp)(fnname, "mysql_init")) {
		    VG_(printf)("this is a bad function %s\n", fnname);
		    return 1;
			}
	    }
	    return 0;
}
static void checkBOF(IRStmt* st, IRDirty* di , IRSB* bb)
{
	int tx;
	tx=0;
 if (st->tag==Ist_WrTmp && st->Ist.WrTmp.data->tag==Iex_Get && st->Ist.WrTmp.data->Iex.Get.offset==20){
	 tx=st->Ist.WrTmp.tmp;

 }

}
static void checkIfVulnerable(IRStmt* st, IRDirty* di , IRSB* bb)
{

	Vuls_DB[0].tag = 0;
	Vuls_DB[0].Container.Ist_Container.tag = Ist_WrTmp;
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_DivModS64to32;
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;/* (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2->tag = Iex_RdTmp;
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp = (IRTemp*) VG_(malloc)("IRTemp", sizeof(IRTemp));
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp;
	Vuls_DB[0].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32 = 0;*/

	Vuls_DB[7].tag = 0;
		Vuls_DB[7].Container.Ist_Container.tag = Ist_WrTmp;
		Vuls_DB[7].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
		Vuls_DB[7].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
		Vuls_DB[7].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
		Vuls_DB[7].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_DivModU64to32;
		Vuls_DB[7].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
		Vuls_DB[7].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;


	//Null Pointer Reference vulnerability Load in wrtmp
	Vuls_DB[1].tag=0;
	Vuls_DB[1].Container.Ist_Container.tag= Ist_WrTmp;
	Vuls_DB[1].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
	Vuls_DB[1].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
	Vuls_DB[1].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Load;
	Vuls_DB[1].Container.Ist_Container.Ist.WrTmp.data->Iex.Load.addr= NULL;
	Vuls_DB[1].Container.Ist_Container.Ist.WrTmp.data->Iex.Load.end=Not_Important;
	Vuls_DB[1].Container.Ist_Container.Ist.WrTmp.data->Iex.Load.ty=Not_Important;


	//Null pointer reference vulnerability Load in put
	Vuls_DB[2].tag=0;
	Vuls_DB[2].Container.Ist_Container.tag= Ist_Put;
	Vuls_DB[2].Container.Ist_Container.Ist.Put.offset=Not_Important;
	Vuls_DB[2].Container.Ist_Container.Ist.Put.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
	Vuls_DB[2].Container.Ist_Container.Ist.Put.data->tag=Iex_Load;
	Vuls_DB[2].Container.Ist_Container.Ist.Put.data->Iex.Load.addr=NULL;
	Vuls_DB[2].Container.Ist_Container.Ist.Put.data->Iex.Load.end= Not_Important;
	Vuls_DB[2].Container.Ist_Container.Ist.Put.data->Iex.Load.ty=Not_Important;


	//Null pointer reference vulnerability Store
	Vuls_DB[3].tag=0;
	Vuls_DB[3].Container.Ist_Container.tag= Ist_Store;
	Vuls_DB[3].Container.Ist_Container.Ist.Store.addr= (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
	Vuls_DB[3].Container.Ist_Container.Ist.Store.addr= NULL;
	Vuls_DB[3].Container.Ist_Container.Ist.Store.data=(IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
	Vuls_DB[3].Container.Ist_Container.Ist.Store.data= NULL;
	Vuls_DB[3].Container.Ist_Container.Ist.Store.end= Not_Important;


	//int overflow add8
	Vuls_DB[4].Container.Ist_Container.tag = Ist_WrTmp;
			Vuls_DB[4].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
			Vuls_DB[4].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
			Vuls_DB[4].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
			Vuls_DB[4].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_Add8;
			Vuls_DB[4].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
			Vuls_DB[4].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;

		//int overflow add16
			Vuls_DB[5].Container.Ist_Container.tag = Ist_WrTmp;
			Vuls_DB[5].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
			Vuls_DB[5].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
			Vuls_DB[5].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
			Vuls_DB[5].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_Add16;
			Vuls_DB[5].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
			Vuls_DB[5].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;
	//Int Overflow Add32
	Vuls_DB[6].tag = 0;
		Vuls_DB[6].Container.Ist_Container.tag = Ist_WrTmp;
		Vuls_DB[6].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
		Vuls_DB[6].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
		Vuls_DB[6].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
		Vuls_DB[6].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_Add32;
		Vuls_DB[6].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
		Vuls_DB[6].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;

		Vuls_DB[8].tag = 0;
			Vuls_DB[8].Container.Ist_Container.tag = Ist_WrTmp;
			Vuls_DB[8].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
			Vuls_DB[8].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
			Vuls_DB[8].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
			Vuls_DB[8].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_Mul32;
			Vuls_DB[8].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
			Vuls_DB[8].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;

			Vuls_DB[9].tag = 0;
			Vuls_DB[9].Container.Ist_Container.tag = Ist_WrTmp;
			Vuls_DB[9].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
			Vuls_DB[9].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
			Vuls_DB[9].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
			Vuls_DB[9].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_Sub32;
			Vuls_DB[9].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
			Vuls_DB[9].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;

			// width conversion  32to8
			Vuls_DB[10].tag = 0;
			Vuls_DB[10].Container.Ist_Container.tag = Ist_WrTmp;
			Vuls_DB[10].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
			Vuls_DB[10].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
			Vuls_DB[10].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Unop;
			Vuls_DB[10].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.op = Iop_32to8;
			Vuls_DB[10].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.arg = NULL;
			//width conversion 32to16
			Vuls_DB[11].tag = 0;
			Vuls_DB[11].Container.Ist_Container.tag = Ist_WrTmp;
			Vuls_DB[11].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
			Vuls_DB[11].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
			Vuls_DB[11].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Unop;
			Vuls_DB[11].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.op = Iop_32to16;
			Vuls_DB[11].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.arg = NULL;


		//width conversion not32
		Vuls_DB[12].tag = 0;
		Vuls_DB[12].Container.Ist_Container.tag = Ist_WrTmp;
		Vuls_DB[12].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
		Vuls_DB[12].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
		Vuls_DB[12].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Unop;
		Vuls_DB[12].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.op = Iop_Not32;
		Vuls_DB[12].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.arg = NULL;


		//width conversion get 8 or 16
		Vuls_DB[13].tag = 0;
		Vuls_DB[13].Container.Ist_Container.tag = Ist_WrTmp;
		Vuls_DB[13].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
		Vuls_DB[13].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
		Vuls_DB[13].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Get;
		Vuls_DB[13].Container.Ist_Container.Ist.WrTmp.data->Iex.Get.offset = NULL;
		Vuls_DB[13].Container.Ist_Container.Ist.WrTmp.data->Iex.Get.ty = Not_Important;

		Vuls_DB[14].tag = 0;
		Vuls_DB[14].Container.Ist_Container.tag = Ist_WrTmp;
		Vuls_DB[14].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
		Vuls_DB[14].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
		Vuls_DB[14].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
		Vuls_DB[14].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_MullU32;
		Vuls_DB[14].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
		Vuls_DB[14].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;

		Vuls_DB[15].tag = 0;
		Vuls_DB[15].Container.Ist_Container.tag = Ist_WrTmp;
		Vuls_DB[15].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
		Vuls_DB[15].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
		Vuls_DB[15].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Unop;
		Vuls_DB[15].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.op = Iop_CmpEQ8x16;
		Vuls_DB[15].Container.Ist_Container.Ist.WrTmp.data->Iex.Unop.arg= NULL;

		Vuls_DB[16].tag = 0;
		Vuls_DB[16].Container.Ist_Container.tag = Ist_WrTmp;
		Vuls_DB[16].Container.Ist_Container.Ist.WrTmp.tmp = Not_Important;
		Vuls_DB[16].Container.Ist_Container.Ist.WrTmp.data = (IRExpr*) VG_(malloc)("IRExpr", sizeof(IRExpr));
		Vuls_DB[16].Container.Ist_Container.Ist.WrTmp.data->tag= Iex_Binop;
		Vuls_DB[16].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.op = Iop_Shl32;
		Vuls_DB[16].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg1= NULL;
		Vuls_DB[16].Container.Ist_Container.Ist.WrTmp.data->Iex.Binop.arg2 = NULL;


		#define VULS_COUNT 17
		int jint;

	int i = 0;
	for (i = 0 ; i < VULS_COUNT; i++)
	{
		if (Vuls_DB[i].tag == 0) //means statement container
		{
			if (CompareStmt(st,&Vuls_DB[i].Container.Ist_Container)==True)
			{
				//Here we are checking for null pointer reference
				//VG_(printf)("Division By zero detected\n");
					//int match=1;
					char* query="=*0x0)QUERY FALSE;*";
				//ppIRStmt(st);
				//VG_(printf)("the dependency to arg2 is  %d \n", depend_of_tmp(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp));
				//if (st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp != INVALID_TMP && depend_of_tmp(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp)){
					//	VG_(printf)("Division By zero detected\n");
					if ((i==0 || i==7 )&& st->Ist.WrTmp.data->Iex.Binop.arg2->tag!= Iex_Const && st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp!=INVALID_TMP){
						//VG_(printf)("Division By zero detected\n");
						add_dirty2(helperc_div, mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp),  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp));
					   // addStmtToIRSB(bb, st);
					}
					if (i==1 && st->Ist.WrTmp.data->Iex.Load.addr->tag != Iex_Const) {

						//add_dirty3(helperc_null, mkIRExprVec_1(mkIRExpr_HWord((HWord) st)), mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Load.addr->Iex.RdTmp.tmp), mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Load.addr->Iex.RdTmp.tmp));

						add_dirty2(helperc_null, mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Load.addr->Iex.RdTmp.tmp),  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Load.addr->Iex.RdTmp.tmp));


					}
					if(i==2 && st->Ist.Put.data->Iex.Load.addr->tag != Iex_Const){
						 //add_dirty3(helperc_null, mkIRExprVec_1(mkIRExpr_HWord((HWord) st)), mkIRExpr_HWord(st->Ist.Put.data->Iex.Load.addr->Iex.RdTmp.tmp), mkIRExpr_HWord(st->Ist.Put.data->Iex.Load.addr->Iex.RdTmp.tmp));
							add_dirty2(helperc_null, mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Load.addr->Iex.RdTmp.tmp),  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Load.addr->Iex.RdTmp.tmp));

					}
					if (i==3 && st->Ist.Store.addr->tag != Iex_Const){
						 add_dirty2(helperc_null2, mkIRExpr_HWord(st->Ist.Put.data->Iex.RdTmp.tmp ),  mkIRExpr_HWord(st->Ist.Put.data->Iex.RdTmp.tmp));
						//VG_(printf)("cont 3 mathched \n");
					}
					if (i==4 || i==5 ||i==6 || i==8|| i==9 || i==14|| i==16)
					{
						//ppIRStmt(st);
						//VG_(printf)(" $$$$$$ \n");
						UInt size;

						//add_dirty4(helperc_int,mkIRExpr_HWord(st->Ist.WrTmp.tmp) ,mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.RdTmp.tmp),  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg1->Iex.RdTmp.tmp),mkIRExpr_HWord(size));
						// for the constants

			            IRExpr *e1, *e2;
						e1 = st->Ist.WrTmp.data->Iex.Binop.arg1;
			            e2 = st->Ist.WrTmp.data->Iex.Binop.arg2;

			            tl_assert(isIRAtom(e1));
			            tl_assert(isIRAtom(e2));

			            size = (bb->tyenv->types[st->Ist.WrTmp.tmp] != Ity_I1) ? sizeofIRType(bb->tyenv->types[st->Ist.WrTmp.tmp]) * 8 : 1;

			            add_dirty7(helperc_intarth,
			                mkIRExpr_HWord((e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : INVALID_TMP),
			                mkIRExpr_HWord((e2->tag == Iex_RdTmp) ? e2->Iex.RdTmp.tmp : INVALID_TMP),
			                mkIRExpr_HWord(st->Ist.WrTmp.tmp),
			                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.op),
			                (e1->tag == Iex_RdTmp) ? assignNew(bb, e1) : mkIRExpr_HWord(e1->Iex.Const.con->Ico.U32),
			                (e2->tag == Iex_RdTmp) ? assignNew(bb, e2) : mkIRExpr_HWord(e2->Iex.Const.con->Ico.U32),
			                mkIRExpr_HWord(i));

			            //VG_(printf)("ddddd ");

					}
					else if (i == 10)
					{
						add_dirty2(helperc_intconv, mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Unop.arg->Iex.RdTmp.tmp),mkIRExpr_HWord(i));
					}
					else if (i == 11)
					{
						add_dirty2(helperc_intconv32to16, mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Unop.arg->Iex.RdTmp.tmp),mkIRExpr_HWord(i));
					}

					else if (i == 12)
					{
						add_dirty2(helperc_intconvnot32, mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Unop.arg->Iex.RdTmp.tmp),mkIRExpr_HWord(i));
					}

					else if (i == 13)
					{
						jint= st->Ist.WrTmp.data->Iex.Get.ty;
						int size;
						            size = (jint != Ity_I1) ? sizeofIRType(jint) * 8 : 1;

						            add_dirty3(helperc_intget,
						                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Get.offset),
						                mkIRExpr_HWord(st->Ist.WrTmp.tmp),
						                mkIRExpr_HWord(size));
					}
					else if (i==15)
					{
						VG_(printf)("cmpeq8*12 found\n");
					}
			}


		}
		//We want to compare IRExpr in an statement.
		else if (Vuls_DB[i].tag == 1)//means expression container
		{
			//CompareExpr()
		}
	}
}


IRSB* fz_instrument ( VgCallbackClosure* closure,
    IRSB* bb_in,
    VexGuestLayout* layout, 
    VexGuestExtents* vge,
    IRType gWordTy, IRType hWordTy )
{
  Addr current_addr = 0;
  IRSB*   bb;
  Int     i, j;
mycounter=mycounter+1;
//VG_(printf)("the counter is %d \n", mycounter);
  if (gWordTy != hWordTy) {
    /* We don't currently support this case. */
    VG_(tool_panic)("host/guest word size mismatch");
  }

  char* dependency;
  int depend;
  depend=0;
  /* Set up SB */
  bb = deepCopyIRSBExceptStmts(bb_in);
  int result;
    result=0;
  // Copy verbatim any IR preamble preceding the first IMark
  i = 0;
  //VG_(printf)("especial statements:::: \n");
  while (i < bb_in->stmts_used && bb_in->stmts[i]->tag != Ist_IMark) {
    addStmtToIRSB(bb, bb_in->stmts[i]);
    //ppIRStmt(bb_in->stmts[i]);
    //VG_(printf)("\n");

    i++;
  }
  //VG_(printf)("especial statements::::finish %d \n" , i);
  // Iterate over the remaining stmts to generate instrumentation.
  tl_assert(bb_in->stmts_used > 0);
  tl_assert(i >= 0);
  tl_assert(i < bb_in->stmts_used);
  tl_assert(bb_in->stmts[i]->tag == Ist_IMark);

  // Get the first statement, and origAddr from it
 // CLG_ASSERT(sbIn->stmts_used >0);
  //CLG_ASSERT(i < sbIn->stmts_used);
  IRStmt* st;
  st = bb_in->stmts[i];
  if(Ist_IMark == st->tag){
	  Addr origAddr;

  origAddr = (Addr)st->Ist.IMark.addr + (Addr)st->Ist.IMark.delta;
  //CLG_ASSERT(origAddr == st->Ist.IMark.addr
    //                     + st->Ist.IMark.delta);  // XXX: check no overflow

  result=checkfunctionname(origAddr);
  }
  /* Get BB struct (creating if necessary).
   * JS: The hash table is keyed with orig_addr_noredir -- important!
   * JW: Why? If it is because of different chasing of the redirection,
   *     this is not needed, as chasing is switched off in callgrind
   */
  tx=0;
  ebp=0;
  for (/*use current i*/; i < bb_in->stmts_used; i++) {

    IRStmt* st = bb_in->stmts[i];
    IRExpr *addr, *data, *data2,**args, *arg, *e1, *e2;
    IRTemp to = 0; /* gcc warning */
    IRDirty *di;
    UInt size = 0;
    ///command execution
    if (result==0){
    	//VG_(printf)("********** \n");
    }
    if (result==1 ){


        if (!st || st->tag == Ist_NoOp) {
          continue;
        }

    	 switch (st->tag) {
    	      case Ist_IMark:
    	        current_addr = st->Ist.IMark.addr;
    	        break;

    	      case Ist_Put:
    	        tl_assert(isIRAtom(st->Ist.Put.data));
    	        if (st->Ist.Put.data->tag == Iex_RdTmp) {
    	          add_dirty2(helperc_put2,
    	              mkIRExpr_HWord(st->Ist.Put.data->Iex.RdTmp.tmp),
    	              mkIRExpr_HWord(st->Ist.Put.offset));
    	        }
    	        else {
    	          add_dirty2(helperc_put2,
    	              mkIRExpr_HWord(INVALID_TMP),
    	              mkIRExpr_HWord(st->Ist.Put.offset));
    	        }
    	        break;

    	      case Ist_WrTmp:
    	        switch (st->Ist.WrTmp.data->tag) {
    	          case Iex_Const:
    	            to = st->Ist.WrTmp.tmp;
    	            add_dirty2(helperc_rdtmp2,
    	                mkIRExpr_HWord(INVALID_TMP),
    	                mkIRExpr_HWord(to));
    	            break;

    	          case Iex_RdTmp:
    	            to = st->Ist.WrTmp.tmp;
    	            add_dirty2(helperc_rdtmp2,
    	                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.RdTmp.tmp),
    	                mkIRExpr_HWord(to));
    	            break;

    	          case Iex_Load:
    	            addr = st->Ist.WrTmp.data->Iex.Load.addr;
    	            to = st->Ist.WrTmp.tmp;

    	            tl_assert(isIRAtom(addr));

    	            j = st->Ist.WrTmp.data->Iex.Load.ty;
    	            size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;

    	            if (addr->tag == Iex_Const) {
    	              add_dirty4(helperc_load2,
    	                  mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
    	                  mkIRExpr_HWord(INVALID_TMP),
    	                  mkIRExpr_HWord(to),
    	                  mkIRExpr_HWord(size));
    	            }
    	            else if (addr->tag == Iex_RdTmp) {
    	              add_dirty4(helperc_load2,
    	                  addr,
    	                  mkIRExpr_HWord(addr->Iex.RdTmp.tmp),
    	                  mkIRExpr_HWord(to),
    	                  mkIRExpr_HWord(size));
    	            }
    	            break;

    	          case Iex_Get:
    	            j = st->Ist.WrTmp.data->Iex.Get.ty;
    	            size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;
    	            add_dirty3(helperc_get2,
    	                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Get.offset),
    	                mkIRExpr_HWord(st->Ist.WrTmp.tmp),
    	                mkIRExpr_HWord(size));
    	            break;

    	          case Iex_Unop:
    	            arg = st->Ist.WrTmp.data->Iex.Unop.arg;
    	            to = st->Ist.WrTmp.tmp;

    	            tl_assert(isIRAtom(arg));

    	            if (arg->tag == Iex_RdTmp) {
    	              size = (bb->tyenv->types[to] != Ity_I1) ? sizeofIRType(bb->tyenv->types[to]) * 8 : 1;
    	              add_dirty4(helperc_unop2,
    	                  mkIRExpr_HWord(arg->Iex.RdTmp.tmp),
    	                  mkIRExpr_HWord(to),
    	                  mkIRExpr_HWord(size),
    	                  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Unop.op));
    	            }
    	            else {
    	              add_dirty4(helperc_unop2,
    	                  mkIRExpr_HWord(INVALID_TMP),
    	                  mkIRExpr_HWord(to),
    	                  mkIRExpr_HWord(size),
    	                  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Unop.op));

    	            }
    	            break;

    	          case Iex_Binop:
    	            j = 0;
    	            switch (st->Ist.WrTmp.data->Iex.Binop.op) {
    	              case Iop_AddF64 ... Iop_CalcFPRF:
    	                j = 1;
    	                break;
    	              default:
    	                break;
    	            }

    	            e1 = st->Ist.WrTmp.data->Iex.Binop.arg1;
    	            e2 = st->Ist.WrTmp.data->Iex.Binop.arg2;

    	            tl_assert(isIRAtom(e1));
    	            tl_assert(isIRAtom(e2));

    	            size = (bb->tyenv->types[st->Ist.WrTmp.tmp] != Ity_I1) ? sizeofIRType(bb->tyenv->types[st->Ist.WrTmp.tmp]) * 8 : 1;

    	            // this is a floating point operation, we don't care about it
    	            // remove the dependency to the destination register
    	            if (j == 1) {
    	              add_dirty7(helperc_binop2,
    	                  mkIRExpr_HWord(INVALID_TMP),
    	                  mkIRExpr_HWord(INVALID_TMP),
    	                  mkIRExpr_HWord(st->Ist.WrTmp.tmp),
    	                  mkIRExpr_HWord(0),
    	                  mkIRExpr_HWord(0),
    	                  mkIRExpr_HWord(0),
    	                  mkIRExpr_HWord(0));
    	              break;
    	            }

    	            add_dirty7(helperc_binop2,
    	                mkIRExpr_HWord((e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : INVALID_TMP),
    	                mkIRExpr_HWord((e2->tag == Iex_RdTmp) ? e2->Iex.RdTmp.tmp : INVALID_TMP),
    	                mkIRExpr_HWord(st->Ist.WrTmp.tmp),
    	                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.op),
    	                (e1->tag == Iex_RdTmp) ? assignNew(bb, e1) : mkIRExpr_HWord(e1->Iex.Const.con->Ico.U32),
    	                (e2->tag == Iex_RdTmp) ? assignNew(bb, e2) : mkIRExpr_HWord(e2->Iex.Const.con->Ico.U32),
    	                mkIRExpr_HWord(size));
    	            break;
    	            case Iex_Mux0X:
    	                       e1 = st->Ist.WrTmp.data->Iex.Mux0X.expr0;
    	                       e2 = st->Ist.WrTmp.data->Iex.Mux0X.exprX;

    	                       tl_assert(st->Ist.WrTmp.data->Iex.Mux0X.cond->tag == Iex_RdTmp);
    	                       tl_assert(isIRAtom(e1));
    	                       tl_assert(isIRAtom(e2));

    	                       add_dirty5(helperc_mux0x2,
    	                           mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Mux0X.cond->Iex.RdTmp.tmp),
    	                           assignNew(bb, st->Ist.WrTmp.data->Iex.Mux0X.cond),
    	                           mkIRExpr_HWord((e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : INVALID_TMP),
    	                           mkIRExpr_HWord((e2->tag == Iex_RdTmp) ? e2->Iex.RdTmp.tmp : INVALID_TMP),
    	                           mkIRExpr_HWord(st->Ist.WrTmp.tmp));

    	                       break;



    	          case Iex_Triop: // only used by floating point operations
    	            break;

    	          case Iex_GetI:  // only used by floating point operations
    	            break;

    	          default:
    	           // ppIRStmt(st);
    	            //VG_(tool_panic)("Ist_WrTmp: data->tag not handled");
    	            break;
    	        }
    	        break;

    	      case Ist_Store:
    	        data = st->Ist.Store.data;
    	        tl_assert(isIRAtom(data));
    	        tl_assert(isIRAtom(st->Ist.Store.addr));

    	        if (data->tag == Iex_RdTmp) {
    	          j = bb->tyenv->types[data->Iex.RdTmp.tmp];
    	          size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;
    	          if (depend_of_tmp(data->Iex.RdTmp.tmp)) {
    	        	  dependency=deptmp[data->Iex.RdTmp.tmp].cons;
    	        	  depend=1;


    	          }
    	        }
    	        else { // data->tag == Iex_Const
    	          j = typeOfIRConst(data->Iex.Const.con);
    	          size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;
    	        }


    	        add_dirty3(helperc_store2,
    	            (st->Ist.Store.addr->tag == Iex_Const) ? mkIRExpr_HWord(st->Ist.Store.addr->Iex.Const.con->Ico.U32) : st->Ist.Store.addr,
    	            mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

    	        break;


    	      default:
    	        break;
    	    }





    }
    /////////
    if (!st || st->tag == Ist_NoOp) {
      continue;
    }

    if (FZ_(verbose)) {
      VG_(printf)("-> ");
      //ppIRStmt(st);
      //VG_(printf)("\n");
    }
	//ppIRStmt(st);
    //VG_(printf)("\n");

    //checkIfVulnerable(st, di, bb);
  //  checkBOF(st, di, bb);
    // check BOF
    int len;
    UInt add[100];
    	len=0;
    	UInt a,b,c;
    	Addr m;
     if (st->tag==Ist_WrTmp && st->Ist.WrTmp.data->tag==Iex_Get && st->Ist.WrTmp.data->Iex.Get.offset==20)
     {

    	 tx=st->Ist.WrTmp.tmp;

    	 if (bb_in->stmts[i+1]->tag==Ist_WrTmp && bb_in->stmts[i+1]->Ist.WrTmp.data->tag==Iex_Binop &&  bb_in->stmts[i+1]->Ist.WrTmp.data->Iex.Binop.arg1->Iex.RdTmp.tmp==tx)
    	 {

    		check_1=1;


    	 }
     }
    	 if(check_1 )
    	 {
    		 if(st->tag==Ist_WrTmp && st->Ist.WrTmp.data->Iex.Binop.op==Iop_Add32)
    		 {
    			 len=st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32;
        		 data= st->Ist.WrTmp.data->Iex.Binop.arg1;

        		 if(data->tag==Iex_RdTmp &&   (st->Ist.WrTmp.data->Iex.Binop.arg2-> tag == Iex_Const))
        		 {
					add_dirty3(helperc_regebp, mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32),
							mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

        		     		    		    		 //VG_(printf)("the size is %4x \n",bb_in->stmts[i+1]->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32);
				 }

    		 }
    		 if(st->tag==Ist_WrTmp && st->Ist.WrTmp.data->Iex.Binop.op==Iop_Sub32)
    		 {
    		     			 len=st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32;
    		         		 data= st->Ist.WrTmp.data->Iex.Binop.arg1;
    		           		 if(data->tag==Iex_RdTmp &&   (st->Ist.WrTmp.data->Iex.Binop.arg2-> tag == Iex_Const))
    		           		 {
    		         		     		    	        add_dirty3(helperc_regebp2,
    		         		     		       	           mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32) ,
    		         		     		    	        		mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

    		         		     		    		    		 //VG_(printf)("the size is %4x \n",bb_in->stmts[i+1]->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32);
							 }

			 }
    	 //reset check_1
    	 check_1=0;
    	 } //check_1

    	 if (st->tag==Ist_WrTmp && st->Ist.WrTmp.data->tag==Iex_Binop&& st->Ist.WrTmp.data->Iex.Binop.op==Iop_Add32 &&  tx!=0 && st->Ist.WrTmp.data->Iex.Binop.arg1->Iex.RdTmp.tmp==tx && st->Ist.WrTmp.data->Iex.Binop.arg2->tag==Iex_Const)
    	 {
    		 	 	 	 data= st->Ist.WrTmp.data->Iex.Binop.arg1;
    		 	 	 	 add_dirty3(helperc_regebp3,
	         		     		       	           mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32) ,
	         		     		    	        		mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

    	 }
    	 //the above if with tmp second argument -- add with 2 tmp arguments
    	 if (st->tag==Ist_WrTmp && st->Ist.WrTmp.data->tag==Iex_Binop&& st->Ist.WrTmp.data->Iex.Binop.op==Iop_Add32 &&  tx!=0 && st->Ist.WrTmp.data->Iex.Binop.arg1->Iex.RdTmp.tmp==tx && st->Ist.WrTmp.data->Iex.Binop.arg2->tag==Iex_RdTmp)
    	 {
    	     		 	 	 	 data= st->Ist.WrTmp.data->Iex.Binop.arg1;
    	     		 	 	 	 data2= st->Ist.WrTmp.data->Iex.Binop.arg2;
    	     		 	 	 	 add_dirty3(helperc_regebp5,
    	     		 	 	 			(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL ,
    	 	         		     		    	        		mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

    	     	 }
    	 //binop sub32 and const arg2
    	 if (st->tag==Ist_WrTmp && st->Ist.WrTmp.data->tag==Iex_Binop&& st->Ist.WrTmp.data->Iex.Binop.op==Iop_Sub32 &&  tx!=0 && st->Ist.WrTmp.data->Iex.Binop.arg1->Iex.RdTmp.tmp==tx && st->Ist.WrTmp.data->Iex.Binop.arg2->tag==Iex_Const)
    	 {
    		 	 	 	 data= st->Ist.WrTmp.data->Iex.Binop.arg1;
    		 	 	 	 add_dirty3(helperc_regebp4,
	         		     		       	           mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.arg2->Iex.Const.con->Ico.U32) ,
	         		     		    	        		mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

    	 }
    	 //sub32 two arg are tmp
    	 if (st->tag==Ist_WrTmp && st->Ist.WrTmp.data->tag==Iex_Binop&& st->Ist.WrTmp.data->Iex.Binop.op==Iop_Sub32 &&  tx!=0 && st->Ist.WrTmp.data->Iex.Binop.arg1->Iex.RdTmp.tmp==tx && st->Ist.WrTmp.data->Iex.Binop.arg2->tag==Iex_RdTmp)
    	     	 {
    	     	     		 	 	 	 data= st->Ist.WrTmp.data->Iex.Binop.arg1;
    	     	     		 	 	 	 data2= st->Ist.WrTmp.data->Iex.Binop.arg2;
    	     	     		 	 	 	 add_dirty3(helperc_regebp6,
    	     	     		 	 	 			(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL ,
    	     	 	         		     		    	        		mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

    	     	     	 }

    	/* if (bb_in->stmts[i+2]->tag==Ist_Store ){
    		 e1= bb_in->stmts[i+2]->Ist.Store.addr;

    		    		     	 b=(UInt) assignNew(bb, e1);
    		    		          b &= (0xffffffff >> (32 - 32));
    		    		          m=(UWord)b;
    		    		 VG_(printf)("the addr is 0x%x \n",(UWord)(m));
    		    		 //add=a;
    		    		 if(depend_on_addr((UWord)(b),8)){
    		    		     	     		    			 VG_(printf)("TAINTED \n");
    		    		     	     		    		 }
    	 }
    	 if (bb_in->stmts[i+2]->tag==Ist_WrTmp && bb_in->stmts[i+2]->Ist.WrTmp.data->tag==Iex_Load ){
    	     		 e1= bb_in->stmts[i+2]->Ist.WrTmp.data->Iex.Load.addr;
    	     		    		     	 c=(UInt) assignNew(bb, e1);
    	     		    		         // c &= (0xffffffff >> (32 - 32));
    	     		    		 VG_(printf)("the addr is 0x%x \n",c);
    	     		    		 //add=a;
    	     		    		 if(depend_on_addr(addr,32)){
    	     		    			 VG_(printf)("TAINTED \n");
    	     		    		 }
    	     	 }
*/


    /////////////////////////


    switch (st->tag) {
      case Ist_IMark:
        current_addr = st->Ist.IMark.addr;
        break;

      case Ist_Put:
        tl_assert(isIRAtom(st->Ist.Put.data));
        if (st->Ist.Put.data->tag == Iex_RdTmp){
          add_dirty2(helperc_put,
              mkIRExpr_HWord(st->Ist.Put.data->Iex.RdTmp.tmp),
              mkIRExpr_HWord(st->Ist.Put.offset));
        }
        else {
          add_dirty2(helperc_put,
              mkIRExpr_HWord(INVALID_TMP),
              mkIRExpr_HWord(st->Ist.Put.offset));
        }
        break;

      case Ist_WrTmp:
        switch (st->Ist.WrTmp.data->tag) {
          case Iex_Const:
            to = st->Ist.WrTmp.tmp;
            add_dirty2(helperc_rdtmp,
                mkIRExpr_HWord(INVALID_TMP),
                mkIRExpr_HWord(to));
            break;

          case Iex_RdTmp:
            to = st->Ist.WrTmp.tmp;
            add_dirty2(helperc_rdtmp,
                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.RdTmp.tmp),
                mkIRExpr_HWord(to));
            break;

          case Iex_Load:
            addr = st->Ist.WrTmp.data->Iex.Load.addr;
            to = st->Ist.WrTmp.tmp;

            tl_assert(isIRAtom(addr));

            j = st->Ist.WrTmp.data->Iex.Load.ty;
            size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;

            if (addr->tag == Iex_Const) {
              add_dirty4(helperc_load,
                  mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
                  mkIRExpr_HWord(INVALID_TMP),
                  mkIRExpr_HWord(to),
                  mkIRExpr_HWord(size));
            }
            else if (addr->tag == Iex_RdTmp) {
              add_dirty4(helperc_load,
                  addr,
                  mkIRExpr_HWord(addr->Iex.RdTmp.tmp),
                  mkIRExpr_HWord(to),
                  mkIRExpr_HWord(size));
            }
            break;

          case Iex_Get:
            j = st->Ist.WrTmp.data->Iex.Get.ty;
            size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;
            add_dirty3(helperc_get,
                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Get.offset),
                mkIRExpr_HWord(st->Ist.WrTmp.tmp),
                mkIRExpr_HWord(size));
            break;

          case Iex_Unop:
            arg = st->Ist.WrTmp.data->Iex.Unop.arg;
            to = st->Ist.WrTmp.tmp;

            tl_assert(isIRAtom(arg));

            if (arg->tag == Iex_RdTmp) {
              size = (bb->tyenv->types[to] != Ity_I1) ? sizeofIRType(bb->tyenv->types[to]) * 8 : 1;
              add_dirty4(helperc_unop,
                  mkIRExpr_HWord(arg->Iex.RdTmp.tmp),
                  mkIRExpr_HWord(to),
                  mkIRExpr_HWord(size),
                  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Unop.op));
            }
            else {
              add_dirty4(helperc_unop,
                  mkIRExpr_HWord(INVALID_TMP),
                  mkIRExpr_HWord(to),
                  mkIRExpr_HWord(size),
                  mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Unop.op));

            }
            break;

          case Iex_Binop:
            j = 0;
            switch (st->Ist.WrTmp.data->Iex.Binop.op) {
              case Iop_AddF64 ... Iop_CalcFPRF:
                j = 1;
                break;
              default:
                break;
            }

            e1 = st->Ist.WrTmp.data->Iex.Binop.arg1;
            e2 = st->Ist.WrTmp.data->Iex.Binop.arg2;

            tl_assert(isIRAtom(e1));
            tl_assert(isIRAtom(e2));

            size = (bb->tyenv->types[st->Ist.WrTmp.tmp] != Ity_I1) ? sizeofIRType(bb->tyenv->types[st->Ist.WrTmp.tmp]) * 8 : 1;

            // this is a floating point operation, we don't care about it
            // remove the dependency to the destination register
            if (j == 1) {
              add_dirty7(helperc_binop,
                  mkIRExpr_HWord(INVALID_TMP),
                  mkIRExpr_HWord(INVALID_TMP),
                  mkIRExpr_HWord(st->Ist.WrTmp.tmp),
                  mkIRExpr_HWord(0),
                  mkIRExpr_HWord(0),
                  mkIRExpr_HWord(0),
                  mkIRExpr_HWord(0));
              break;
            }

            add_dirty7(helperc_binop,
                mkIRExpr_HWord((e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : INVALID_TMP),
                mkIRExpr_HWord((e2->tag == Iex_RdTmp) ? e2->Iex.RdTmp.tmp : INVALID_TMP),
                mkIRExpr_HWord(st->Ist.WrTmp.tmp),
                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Binop.op),
                (e1->tag == Iex_RdTmp) ? assignNew(bb, e1) : mkIRExpr_HWord(e1->Iex.Const.con->Ico.U32),
                (e2->tag == Iex_RdTmp) ? assignNew(bb, e2) : mkIRExpr_HWord(e2->Iex.Const.con->Ico.U32),
                mkIRExpr_HWord(size));
            break;

          case Iex_Mux0X:
            e1 = st->Ist.WrTmp.data->Iex.Mux0X.expr0;
            e2 = st->Ist.WrTmp.data->Iex.Mux0X.exprX;

            tl_assert(st->Ist.WrTmp.data->Iex.Mux0X.cond->tag == Iex_RdTmp);
            tl_assert(isIRAtom(e1));
            tl_assert(isIRAtom(e2));

            add_dirty5(helperc_mux0x,
                mkIRExpr_HWord(st->Ist.WrTmp.data->Iex.Mux0X.cond->Iex.RdTmp.tmp),
                assignNew(bb, st->Ist.WrTmp.data->Iex.Mux0X.cond),
                mkIRExpr_HWord((e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : INVALID_TMP),
                mkIRExpr_HWord((e2->tag == Iex_RdTmp) ? e2->Iex.RdTmp.tmp : INVALID_TMP),
                mkIRExpr_HWord(st->Ist.WrTmp.tmp));

            break;

          case Iex_Triop: // only used by floating point operations
            break;

          case Iex_GetI:  // only used by floating point operations
            break;

          case Iex_CCall:
            // XXX - x86g_calculate_condition
            // look at guest_x86_spechelper
            // encounterd when IR optimization failed
            if (VG_(strcmp)(st->Ist.WrTmp.data->Iex.CCall.cee->name, "x86g_calculate_condition") == 0) {
              args = st->Ist.WrTmp.data->Iex.CCall.args;
              tl_assert(args[0]->tag == Iex_Const && args[0]->Iex.Const.con->tag == Ico_U32);
              //tl_assert(args[1]->tag == Iex_RdTmp);
              if (args[1]->tag == Iex_RdTmp) {
                tl_assert(args[2]->tag == Iex_RdTmp);
                tl_assert(args[3]->tag == Iex_RdTmp);
                tl_assert(args[4]->tag == Iex_RdTmp);

                add_dirty7(helperc_x86g_calculate_condition,
                    mkIRExpr_HWord(st->Ist.WrTmp.tmp),               // to
                    mkIRExpr_HWord(args[0]->Iex.Const.con->Ico.U32), // cond
                    args[1],                                         // cc_op
                    mkIRExpr_HWord(args[2]->Iex.RdTmp.tmp),          // cc_dep1
                    mkIRExpr_HWord(args[3]->Iex.RdTmp.tmp),          // cc_dep2
                    args[2],                                         // cc_dep1
                    args[3]);                                        // cc_dep2
              }
              else {
                //VG_(printf)("oops, we depend of x86g_calculate_condition: %d, %d\n", args[0]->Iex.Const.con->Ico.U32, args[1]->Iex.Const.con->Ico.U32);
                //VG_(tool_panic)("");
                // just remove the dependency
                add_dirty2(helperc_rdtmp,
                    mkIRExpr_HWord(INVALID_TMP),
                    mkIRExpr_HWord(st->Ist.WrTmp.tmp));
              }
            }
            else {
              // just remove the dependency
              add_dirty2(helperc_rdtmp,
                  mkIRExpr_HWord(INVALID_TMP),
                  mkIRExpr_HWord(st->Ist.WrTmp.tmp));
            }
            break;

            //case Iex_Binder:
            //    break;

            //case Iex_Qop:
            //    break;

          default:
           // ppIRStmt(st);
            VG_(tool_panic)("Ist_WrTmp: data->tag not handled");
            break;
        }
        break;

      case Ist_Store:
        data = st->Ist.Store.data;
        tl_assert(isIRAtom(data));
        tl_assert(isIRAtom(st->Ist.Store.addr));

        if (data->tag == Iex_RdTmp) {
          j = bb->tyenv->types[data->Iex.RdTmp.tmp];
          size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;
          if (depend_of_tmp(data->Iex.RdTmp.tmp)) {
        	  dependency=deptmp[data->Iex.RdTmp.tmp].cons;
        	  depend=1;


          }
        }
        else { // data->tag == Iex_Const
          j = typeOfIRConst(data->Iex.Const.con);
          size = (j != Ity_I1) ? sizeofIRType(j) * 8 : 1;
        }

        add_dirty3(helperc_store,
            (st->Ist.Store.addr->tag == Iex_Const) ? mkIRExpr_HWord(st->Ist.Store.addr->Iex.Const.con->Ico.U32) : st->Ist.Store.addr,
            mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : INVALID_TMP),(data->tag == Iex_RdTmp) ? assignNew(bb, data):NULL);

        break;

      case Ist_Exit:
        tl_assert(st->Ist.Exit.guard->tag == Iex_RdTmp);
        add_dirty3(helperc_exit,
            mkIRExpr_HWord(st->Ist.Exit.guard->Iex.RdTmp.tmp),
            mkIRExpr_HWord(current_addr),
            assignNew(bb, st->Ist.Exit.guard));
        break;

      case Ist_PutI:
        //VG_(printf)("oops, tag Ist_PutI not handled at 0x%08x\n", current_addr);
        break;
      case Ist_NoOp:
      case Ist_AbiHint:
      case Ist_MBE:
      case Ist_Dirty:
      default:
        break;
    }

    /* must be after the switch, otherwise Ist_Exit can jump causing helper
       not to be called */
    addStmtToIRSB(bb, st);
  }

  return bb;
}

