#!/usr/bin/env python

#   This file is part of Fuzzgrind.
#   Copyright (C) 2009 Gabriel Campana
#
#   This work is licensed under the terms of the GNU GPL, version 3.
#   See the LICENSE file in the top-level directory.

import random
import getopt
import os
import re
import shutil
import subprocess
import sys
import time
import numpy as np
from config import *
from valgrind import *
from stp import *
from score import *
from fault_checker import *

import session


def get_input(filename):
    '''
    Load a file, and return it's content
    
    @param filename: name of the file to load
    @type  filename: str
    '''
    
    fp = open(filename)
    buf = fp.read()
    fp.close()
    
    return buf
    
    
class Input:
    def __init__(self, number, filename, bound, bytes=None):
        self.number = number
        self.filename = filename
        self.bound = bound
        if not bytes:
            self.bytes = get_input(filename)
        else:
            fp = open(filename, 'w')
            fp.write(bytes)
            fp.close()
            self.bytes = bytes


def constraint_implies(c1, c2):

    #print 'check ' + c1.pp() + ' => ' +c2.pp()
    if c1.pp() == c2.pp():
        return True
    
    if c1.name == c2.name == 'unop' and c1.op.op == 'Not1':
        c1 = c1.arg
        c2 = c2.arg
        if c1.name == c2.name == 'binop' and (c1.op, c1.size) == (c2.op, c2.size):
            if c1.op.op == 'CmpLE32S':
                c1 = c1.arg1
                c2 = c2.arg1
    
                if c1.name == c2.name == 'binop' and \
                   (c1.op, c1.arg1.pp(), c1.size) == (c2.op, c2.arg1.pp(), c2.size):
                    binop = c1.op.op
                    if binop == 'Sub32' and c1.arg2.name == 'const' and c2.arg2.const == 'const' and \
                      c1.arg2.const.value < c2.arg2.const.value:
                        return True
    return False
#change value based constraint subsumption
"""
    if c1.name == c2.name == 'unop' and c1.op.op == 'Not1':
        c1 = c1.arg
        c2 = c2.arg
        if c1.name == c2.name == 'binop' and (c1.op, c1.size) == (c2.op, c2.size):
            if c1.op.op == 'CmpEQ32':
                c1 = c1.arg1
                c2 = c2.arg1
    
                if c1.name == c2.name == 'binop' and \
                   (c1.op, c1.arg1.pp(), c1.size) == (c2.op, c2.arg1.pp(), c2.size):
                    binop = c1.op.op
                    if binop == 'Sub32' and c1.arg2.name == 'const' and c2.arg2.const == 'const' and \
                      c1.arg2.const.value < c2.arg2.const.value:
                        return True
"""               


def contraint_subsumption(constraints, new_c, stp):
    '''
    Check whether new_c definitely implies or is definitely implied by another
    constraint.
    
    @param constraints: constraint list
    @type  constraints: Iex list
    @param new_c:       new constraint
    @type  new_c:       Iex
    @param stp:
    @type  stp:         STP
    @param taken:
    @type  taken:       boolean
    '''            
    
    if CONSTRAINT_SUBSUMPTION:
        for c in constraints:
            # c => new_c
            if constraint_implies(c['expr'], new_c):
                return constraints
        
        result = []
        for c in constraints:
            # new_c => c                   
            if not constraint_implies(new_c, c['expr']):
                result.append(c)
            else:
                print 'new_c => c'
    else:
        result = constraints
            
    # don't store stp formula, only query number !
    # stp.query can be modified if two queries depend of same variables with
    # different size (eg. LDle:I8(input(0)) AND LDle:I32(input(0)))
    # print new_c.pp()
    try:
        stp_formula = stp.from_expr_(new_c)
    except STPShiftError, error:
        if DEBUG_LAST:
            print '    ! %s. Skipping constraint!' % error,
        return result
    stp.query.append(stp_formula)
    result.append({ 'expr': new_c, 'n': len(stp.query) - 1 })
    
    return result


def compute_path_constraint(input_file,  callbacks):
    '''
    Get the path constraints for a given input
    
    @param input_file: input filename
    @type  input_file: str
    @return str list
    '''
    
    if not DEBUG_LAST:
        output_filename = run_valgrind(PARAM['PROGNAME'],
                                       PARAM['PROGARG'],
                                       input_file,
                                       taint_stdin=PARAM['TAINT_STDIN'],
                                       max_constraint=PARAM['MAX_BOUND'])
    else:
        output_filename = DEBUG_LAST
    global counter
    pc_counter=0
    counter =0
    global vul
    global countintsub
    global countintwidth32to16
    global countintwidth32to8
    global countintwidthnot32
    global countintmulu
    global countintget
    global countintmulsigned
    global countintaddu
    global countintaddsigned
    global countnull
    global counntdiv
    countnull=0
    countdiv=0
    countintsub=0
    countintwidth32to16=0
    countintwidth32to8=0
    countintwidthnot32=0
    countintmulu=0
    countintget=0
    countintmulsigned=0
    countintaddu=0
    countintaddsigned=0
    path_counter=0


    global realtest
    realtest=[]
    pc = [] # concolic execution
    pc2=[] # division by zero
    pc3=[] # null pointer reference
    pc4=[] #int overflow
    vul=[]
    bof_path_counters=[]
    bof_maxes=[]
    bof_mins=[]
    bof_lens=[]
    bof_cu_funs=[]
    bof_var_funs=[]
    bof_counter=0
    addresses=[]
    bof_cons=[]  
    lengths=[]
    global tainted_bytes
    tainted_bytes=[]
    pathconst=[]
    fp = open(output_filename, 'r')
    for line in fp:
        m = re.match('\[\+\] 0x[0-9]+.* depending on input: if \((.*)\) => (\d)', line)
        if m:   
            #print '    + constraint\t%s' % (constraint[:100])    
            int_dep=re.match('\[\+\] 0x011111+.* \((.*)\)', line)
            if int_dep and check_int:
                vul.append('int-dep')
            if int_dep and not check_int:
                continue
            if not int_dep:
                vul.append('dep')   
            constraint = m.group(1)
            taken = bool(int(m.group(2)))
            pathconst.append(constraint)
            pc.append((constraint, taken))
            path_counter=path_counter +1

            cst_sw=0
#            for cst in pathconst: 
#                if m.group(1)==cst:
#                    cst_sw=1
#            if cst_sw==0:    
#                constraint = m.group(1)
#                taken = bool(int(m.group(2)))
#                pathconst.append(constraint)
#                pc.append((constraint, taken))
#                path_counter=path_counter +1

            counter=counter +1
        m=  re.match('\[\+\] 0x[0-9]+.* division by zero: if \((.*)\)', line)
        if m and check_div:
            counter=counter +1
            constraint = m.group(1)
            taken=False
            vul.append('division by zero')
            realtest.append(0)
            pc.append((constraint, taken))
            # call check vul then  remove last pc2 item and continue
            #break
        m=  re.match('\[\+\] 0x[0-9]+.* null pointer reference: if \((.*)\)', line)
        if m and check_null:
            counter= counter +1
            constraint = m.group(1)
            taken=False
            realtest.append(0)
            vul.append('null pointer reference')
            pc.append((constraint, taken))
            # call check vul then  remove last pc2 item and continue
            #break
        feasible=True
        taken=False
        m=  re.match('\[\+\] 0x[0-9]+.* int overflow: if \((.*)\)', line)
        if m and check_int:
            constraint = m.group(1)
            get_conv=re.match('\[\+\] 0x999+.* \((.*)\)', line)
            if get_conv:
                get_conv_add=re.match('.*Add.*', constraint)
                get_conv_sub=re.match('.*Sub.*', constraint)
                get_conv_mul=re.match('.*Mul.*', constraint)
                taken=False
                if  not get_conv_add and not get_conv_sub and not get_conv_mul :
                    feasible=False
            if feasible:
                counter= counter +1
                
                m3=  re.match('\[\+\] 0x3216+.* \((.*)\)', constraint)
                if m3:
                    realtest.append(1)
                    
                else: 
                    realtest.append(0)
                m3=  re.match('\[\+\] 0x1919+.* \((.*)\)', line)
                if m3:
                    vul.append('int-sub')
                m3=  re.match('\[\+\] 0x9111+.* \((.*)\)', line)
                if m3:
                    vul.append('int-width-32to16')
                m3=  re.match('\[\+\] 0x1010+.* \((.*)\)', line)
                if m3:
                    vul.append('int-width-32to8')
                m3=  re.match('\[\+\] 0x1212+.* \((.*)\)', line)
                if m3:
                    vul.append('int-width-not32')
                m3=  re.match('\[\+\] 0x141+.* \((.*)\)', line)
                if m3:
                    vul.append('int-mul-u')
                m3=  re.match('\[\+\] 0x999+.* \((.*)\)', line)
                if m3:
                    vul.append('int-get')
                m3=  re.match('\[\-+\] 0x888+.* \((.*)\)', line)
                if m3:
                    vul.append('int-mul-signed')
                    taken=False
                m3=  re.match('\[\+\] 0x6666+.* \((.*)\)', line)
                if m3:
                    vul.append('int-add-u')
                m3=  re.match('\[\+\] 0x4568+.* \((.*)\)', line)
                if m3:
                    vul.append('int-add-signed')
                #constraint="32to1(1Uto32(CmpNE64(And64(Add64(32Uto64(8Sto32(LDle:I8(input(2)))),32Uto64(8Sto32(0x1:I8))),0xffffffff00000000:I64),0x00:I64)))"
               # constraint=constraint.replace('8Uto32(LDle:I8(input(', '8Sto32(LDle:I8(input(')
                #constraint=constraint.replace('16Uto32(LDle:I16(input(', '16Sto32(LDle:I16(input(')
                
                pc.append((constraint, taken))
                # call check vul then  remove last pc2 item and continue
                #break
                    
        m = re.match('const is+.*input\((\d)\)', line)
        if m:   
                    tainted_bytes.append(int(m.group(1)))
                    pc_counter=path_counter
        m=re.match('address=> 0x(.*) @@@ const => \((.*)\) @@@ len => \((.*)\) @@@ fnname => \((.*)\) @@@ infn => \((.*)\)', line)
        swch=0
        if m:
                    bof_length=int(m.group(3))
                    bof_const=m.group(2)
                    bof_var_fun=m.group(4)
                    bof_cur_fn=m.group(5)
                    print bof_cur_fn
#                    print bof_var_fun
                    #bof_const="GET:I8(PUT(8Uto32(LDle:I8(input(15),sdkjhskdjfhaskdinput(17)) input(123)))"
                    m4=re.findall("input\((\d+)\)", bof_const)
                    m4.reverse()
                    for inputs_found in m4:    
                        bof_byte=int(inputs_found)
                        if(len(bof_maxes)==0):
                            bof_lens.append(bof_length)
                            bof_mins.append(bof_byte)
                            bof_maxes.append(bof_byte)
                            bof_cu_funs.append(bof_cur_fn)
                            bof_var_funs.append(bof_var_fun)
                            bof_path_counters.append(path_counter)
                            bof_counter=bof_counter+1
                        else:
                            mysw1=0 # it will be 1 if the byte number exists in the range of the same function
                            loop_cnt=-1
                            for x in bof_cu_funs:
                                loop_cnt=loop_cnt+1
                                if x==bof_cur_fn:
                                        if bof_byte<=bof_maxes[loop_cnt]+1 and bof_byte>=bof_mins[loop_cnt]-1:
                                            mysw1=1

                            mysw=0
                            loop_cnt=-1
                            for x in bof_cu_funs:
                                loop_cnt=loop_cnt+1
                                if x==bof_cur_fn:
                                    #if  bof_var_fun==bof_var_funs[loop_cnt] :
                                    mysw=1
                                    if mysw1==1:
                                        if bof_byte<=bof_maxes[loop_cnt]+1 and bof_byte>=bof_mins[loop_cnt]-1:
                                            if bof_byte==bof_maxes[loop_cnt]+1 or bof_byte==bof_maxes[loop_cnt]:
                                                bof_maxes[loop_cnt]=bof_byte
                                                bof_path_counters[loop_cnt]=path_counter
                                                if bof_lens[loop_cnt]<bof_length:
                                                    bof_path_counters[loop_cnt]=path_counter
                                                    bof_lens[loop_cnt]=bof_length
                                            elif bof_byte==bof_mins[loop_cnt]-1 or bof_byte==bof_mins[loop_cnt]:
                                                bof_mins[loop_cnt]=bof_byte
                                                if bof_lens[loop_cnt]<bof_length:
                                                    bof_lens[loop_cnt]=bof_length
                                                    bof_path_counters[loop_cnt]=path_counter
                                    else:
                                        bof_lens.append(bof_length)
                                        bof_mins.append(bof_byte)
                                        bof_maxes.append(bof_byte)
                                        bof_cu_funs.append(bof_cur_fn)
                                        bof_var_funs.append(bof_var_fun)
                                        bof_path_counters.append(path_counter)
                                        bof_counter=bof_counter+1
                                        mysw1=1
                                        mysw=1
                            if mysw==0:
                                bof_lens.append(bof_length)
                                bof_mins.append(bof_byte)
                                bof_maxes.append(bof_byte)
                                bof_cu_funs.append(bof_cur_fn)
                                bof_var_funs.append(bof_var_fun)
                                bof_path_counters.append(path_counter)
                                bof_counter=bof_counter+1
                                                        
        elif line == "If that doesn't help, please report this bug to: www.valgrind.org\n" or \
          ('oops, we depend of x86g_calculate_condition' in line and False):
            print '[-] Oops, a bug occured in Valgrind. See /tmp/valgrind_output.txt'
            sys.exit(-1)
        if len(pc) == PARAM['MAX_BOUND']:
            break
    fp.close()
#    for i in vul:
#        print i
    print 'the path counter ',  path_counter
    return pc, bof_maxes, bof_mins, bof_lens, bof_path_counters, bof_cu_funs, vul


def expand_execution(input, callbacks):
    '''
    Symbolically execute the program under test with that input, and generate
    new input computed from the expanded path constraints
    
    @param input: input to expand
    @type  input: Input instance
    @return new inputs
    '''
    global ninput
    global paths
    global elapsed
    global querytime
    global pathssub
    global totalcon
    global cva_constraints
    global cva_paths
    
    callback_start_constraint_solver = callbacks[0]
    callback_constraint_solved = callbacks[1]
    callback_start_constraint_analyser = callbacks[2]
    callback_constraint_analysed = callbacks[3]
    callback_start_expander = callbacks[4]
    callback_expanded = callbacks[5]
    detected=[]
    stp = STP()
    stp2=STP()
    threshold = 0
    constraints = []
    constraints2 = []
    child_inputs = []
    vul_inputs=[]
    bof_start=time.time()
    # compute path constraint

    if not callback_start_expander:
        print '[+] expanding execution with file %s ' % input.filename.split('/')[-1]
    else:
        callback_start_expander(input)

    
    if input.bound in cva_paths:
	print 'CVA: Paths Pruned'
        pc = cva_paths[input.bound]
	#return child_inputs	
    else:
        start = time.time()
	pc, bof_maxes, bof_mins, bof_lens, bof_path_counters , bof_cur_funs, vul= compute_path_constraint(input.filename,  callbacks)

    	querytime = querytime + (time.time() - start)

    if callback_expanded:
        callback_expanded()
    #print '[+] here'
    #parse valgrind's output and do constraint subsumption
    if not callback_start_constraint_analyser:
        print '    * %d path constraints (bound: %d)' % (len(pc), input.bound)
        os.write(sys.stdout.fileno(), '       ')
    else:
        callback_start_constraint_analyser(len(pc))
    j = 1
    pc_counter_bof=0
    for (c, taken) in pc:
        #print c,'   ',taken 
        print 'this is the const',  c
        if not taken:
            c = 'Not1(%s)' % c
        expr = parse_expr(c)
        constraints = contraint_subsumption(constraints, expr, stp) # is input.bound still consistent ?
        #Buffer Overflow Detection
        constraints2 = contraint_subsumption(constraints2, expr, stp2)
        pc_counter_bof=pc_counter_bof+1
        bof_cnt1=-1
        could_not_solved=0 #stp could not solved previous bof
        for path_cnt in bof_path_counters:
            bof_cnt1=bof_cnt1+1
            print 'number of bof const is',  len(bof_path_counters)
          #  if (((loop>=path_cnt-1 or loop<=path_cnt+1) and could_not_solved==1) or loop==path_cnt-1 ):
            if (pc_counter_bof>=path_cnt-1 or pc_counter_bof<=path_cnt+1) :
                print "solving bof const for function:", bof_cur_funs[bof_cnt1]
                stp2.execute2()
                #stp.bof_query(bof_lens[bof_cnt1], bof_mins[bof_cnt1], bof_maxes[bof_cnt1])
                stp2.bof_query(bof_lens[bof_cnt1], bof_mins[bof_cnt1], bof_maxes[bof_cnt1])
                stp2.execute3()
                solution_bof=stp2.interpret2()
                bytes =[]
                solution_cnt=0
                size=8
                if solution_bof:
                    for x in solution_bof:
                        for i in range(0, size / 8):
                            if x==0:
                                    x=random.randint(1, 127)    
                            bytes.append(chr((x >> (i * 8)) & 0xff))
                    fp = open('/tmp/input.txt', 'w')
                    bytes.reverse()
                    bytes.append(chr((0 >> (i * 8)) & 0xff))
                    np.array(bytes).tolist()
                    bytes = ''.join(bytes)
                    fp.write(str(bytes))
                    fp.close()
                    print "the bof solution is",  bytes,  'with the len', str(bof_lens[bof_cnt1]) ,"for constraint", str(bof_path_counters[bof_cnt1])
                    fault = check(PARAM['PROGNAME'], PARAM['PROGARG'], "/tmp/input.txt", PARAM['FAULT_CHECKER'], PARAM['TAINT_STDIN'])
#                    try:
#                                raw_input("Press enter to continue")
#                    except SyntaxError:
#                                pass                    
                    if fault:
                        
                        detect_sw=0
                        for is_detected in detected:
                            if path_cnt==is_detected:
                                detect_sw=1
                        if detect_sw==0:        
                            detected.append(path_cnt)
                            print "#################################"
                            print "BOF DETECTED"
                            print "#################################"
                            bof_end=time.time()
                            bof_time=bof_end-bof_start
                            print "the time is " ,  bof_time
                            try:
                                raw_input("Press enter to continue")
                            except SyntaxError:
                                pass
                        could_not_solved=0
                else:
                    could_not_solved=1
                   # print "cannot solve the const for bof_count", loop
                    print ":((((((((((((((((((((((((((((("
                    print ":((((((((((((((((((((((((((((("
                    print ":((((((((((((((((((((((((((((("
#                try:
#                                raw_input("Press enter to continue")
#                except SyntaxError:
#                                pass
        #Buffer Overflow Detection
        

# is input.bound still consistent ?
        stp.first_cmp = True # XXX - dirty
        if not callback_constraint_analysed:
            os.write(sys.stdout.fileno(), '%s%d' % ('\b' * len(str(j - 1)), j))
        else:
            callback_constraint_analysed()
        j += 1
    if not callback_constraint_analysed:
        os.write(sys.stdout.fileno(), '%s' % '\b' * (len(str(j - 1)) + 6))

    totalcon += len(pc)
     
    if len(constraints) != len(pc):
        print '    * %d path constraints (thanks to constraint subsumption)' % len(constraints)
        pathssub += len(constraints)
    
    # all queries are computed, there will not be change anymore, so we can
    # safely create the constraints
    loop=-1

    for c in constraints:
        c['stp'] = stp.query[c.pop('n')]
    stp.query = []
    #we have changed input.bound to zero for test

    #input.bound=0
    if input.bound > len(constraints):
        return child_inputs,  vul_inputs
    elif input.bound > 0:
        # XXX - we should reuse previous stp.query
        for j in range(0, input.bound):
           if vul[j]=='dep':
            stp.query = [ constraints[j]['stp'] ]
        stp.negate(len(stp.query) - 1)
    
    if callback_start_constraint_solver:
        callback_start_constraint_solver(len(constraints) - input.bound)

    #CVA for infeasible paths    
    
    #infeasible_constraints = []
    
    
    # solve constraints
    for j in range(input.bound, len(constraints)):
        if not callback_constraint_solved:
            print '    * solving constraints [0:%d]' % j
        
        value = constraints[j]['stp'].pp()
        #print value
        if value in cva_constraints:
		#print cva_constraints[value]
	        print 'CVA: Constraints Pruned'
		solution = cva_constraints[ value ]
		#if callback_constraint_solved:
	        #        callback_constraint_solved(None)
                #continue
		
        else:
		if stp.query:
		    stp.negate(len(stp.query) - 1)
		
		    if DEBUG_LAST:
		        print '     ', constraints[j-1]['expr'].pp()
		        print '     ', constraints[j-1]['stp'].pp()
		    if DEBUG_LAST or VERIF_SOLVABLE:
		        stp.execute()
		        if not stp.interpret():
		            stp.query.pop()
		            print '    ! unsolvable constraint, skipping it !'
		            sys.exit(0)
		            if callback_constraint_solved:
		                callback_constraint_solved(None)
		            break
		
		#print '***', constraints[j]['stp'].pp()
		
		stp.query += [ constraints[j]['stp'] ]
		stp.negate(len(stp.query) - 1)
		#start = time.time()
        loop=j
        print j
        print vul[loop]
        
        stp.execute()
        
                #if realtest[loop]==1:
                    #print 'this is the intoverflow'
		#querytime = querytime + (time.time() - start)
        solution = stp.interpret()
	       	#print '%s' % solution
       	paths += 1
        if loop <counter:
                print 'solved the vulnerability ',loop,   vul[loop]
                if debug:
                    try:
                        raw_input("Press enter to continue")
                    except SyntaxError:
                        pass
                if vul[loop]!='dep' and vul[loop]!='int-dep':
                    stp.query.pop()
                    if loop>0:
                        if vul[loop-1]=='int-dep':
                            stp.query.pop()
			    if loop-1>0:	
			            if vul[loop-2]=='int-dep':
			                    stp.query.pop()
#                if (vul[loop]=='int-sub'):
#                    countintsub+=1
#                if (vul[loop]=='int-width-32to16'):
#                    countintwidth32to16+=1    
#                if (vul[loop]=='int-width-32to8'):
#                        countintwidth32to8+=1
#                if (vul[loop]=='int-width-not32'):
#                    countintwidthnot32+=1
#                if (vul[loop]=='int-mul-u'):
#                    countintmulu+=1
#                if (vul[loop]=='int-get'):
#                    countintget+=1
#                if (vul[loop]=='int-mul-signed'):
#                    countintmulsigned+=1
#                if (vul[loop]=='int-add-u'):
#                    countintaddu+=1
#                if (vul[loop]=='int-add-signed'):
#                    countintaddsigned+=1
#                if (vul[loop]=='null pointer reference'):
#                        countnull=1+countnull
#                if (vul[loop]=='division by zero'):
#                    countdiv+=1
                                      
        if PARAM['PATH_BOUND'] > 0 and paths >= PARAM['PATH_BOUND']:
		return child_inputs

	if CONSTRAINT_SUBSUMPTION:
        	cva_constraints[value] = solution

        if solution:
	    if CONSTRAINT_SUBSUMPTION:
           	 cva_paths[input.bound] = pc
            bytes = list(input.bytes)
        
            for (byte, (value, size)) in solution.iteritems():
                for i in range(0, size / 8):
                    bytes[byte + i] = chr((value >> (i * 8)) & 0xff)
            bytes = ''.join(bytes)
            ########## # Buffer Overflow
            
            
            
            ###########Buffer Overflow
            print 'the solution is ',  bytes, 'for text file', ninput+1
            
            ninput += 1
            print 'loop is',  loop
#            print 'vul[loop] is ',  vul[loop]
#            filename = '%s%s%d%s' % (PARAM['OUTPUT_FOLDER'], vul[loop],ninput, PARAM['EXTENSION'])
            filename = '%s%d%s' % (PARAM['OUTPUT_FOLDER'],ninput, PARAM['EXTENSION'])
            if interactive  and vul[loop]!='dep' and vul[loop]!='int-dep':
                    try:
                        raw_input("Press enter to continue")
                    except SyntaxError:
                        pass
            #pathqueryfile = '%s%d%s' % (PARAM['OUTPUT_FOLDER'], ninput,'.stp')
            #f = open(pathqueryfile, 'w')
            #f.write(stp.pp())
            #f.close()
            
            if vul[loop]=='dep':
                new_input = Input(ninput, filename, j + 1, bytes)
                child_inputs.append(new_input)
                vul_inputs.append(new_input)
            if vul[loop]!='dep':
                new_input = Input(ninput, filename, j + 1, bytes)
                vul_inputs.append(new_input)    


            if not callback_constraint_solved:
                printable_bytes = re.sub('[^\w;\.!\*&~"#\'\{\}\(\)\[\]]', '.', bytes[:10])
                #print '    * new_input (%d%s): %s time_taken : %s' % (ninput, PARAM['EXTENSION'], printable_bytes, elapsed)
		print '    * new_input (%d%s%s): %s' % (ninput,vul[loop], PARAM['EXTENSION'], printable_bytes)
        
        
                #fname = 'time_results_%s' % PARAM['INPUT_FILE'].split('/')[-1]
                #f = open(fname, 'a')
                #f.write('%s,%s\n' % (printable_bytes,elapsed))
	        #f.close()
            else:
                callback_constraint_solved(new_input)
        else:
            # add infesible constraint
            #print '%s' % solution 
            if callback_constraint_solved:
                callback_constraint_solved(None)

    if DEBUG_LAST:
        sys.exit(0)
    
    return child_inputs, vul_inputs


def search(target, worklist, callbacks):    
    global ninput
    global paths
    global elapsed
    global querytime
    global start
    global pathssub
    global totalcon
    global cva_constraints
    global cva_paths
    global vul_inputs
    vul_inputs=[]
    callback_start_scoring = callbacks[6]
    callback_scored = callbacks[7]
    
    callback_start_check = callbacks[8]
    callback_checked = callbacks[9]

    accumlist = list(worklist)
    current = ninput
    #session.save(target, PARAM, ninput, worklist)  
    
    #start = time.time()

    while worklist:
        print_tofile= 'Paths Explored: %s Feasible Paths: %s Total Constraints: %s Actual Constraints: %s Time Taken: %s Valgrind Time: %s \n'\
              % (paths,ninput - current,totalcon,pathssub,round(elapsed,2),round(querytime,2))
        fp = open(faulty_inputs, 'a')
        fp.write(print_tofile)
    

        #start = time.time()
        input = worklist.pop()
        #print '[+] input %s' % input.filename

        child_inputs, vul_inputs = expand_execution(input, callbacks)

        if USE_ACCUM:
		continue         
 
	if PARAM['PATH_BOUND'] > 0 and paths >= PARAM['PATH_BOUND']:
           if not USE_ACCUM:
		accumlist += child_inputs
           break;

        if not callback_start_check:
            print '[+] checking each new input'
        else:
            callback_start_check(len(child_inputs))

        for input in vul_inputs:
            if not callback_checked:
                os.write(sys.stdout.fileno(), '    %s' % input.filename.split('/')[-1])
            fault = check(PARAM['PROGNAME'], PARAM['PROGARG'], input.filename, PARAM['FAULT_CHECKER'], PARAM['TAINT_STDIN'])
            if not callback_checked:
                os.write(sys.stdout.fileno(), '\b' * (len(input.filename.split('/')[-1]) + 4))
                if fault:
                    print '[+] ' + ('@' * 75)
                    print '    Fault detected on file %s' % input.filename.split('/')[-1]
                    print '    ' + ('@' * 75)
                    fp = open(faulty_inputs, 'a')
                    fp.write( 'Fault detected on file %s \n' % input.filename.split('/')[-1])
                    fp.close()
            else:
                callback_checked(input.number, fault)
            if fault:
                filecopy = os.path.join(PARAM['CRASH_FOLDER'], os.path.basename(input.filename))
                shutil.copy(input.filename, filecopy)

        #elapsed = elapsed + (time.time() - start)

	if not callback_start_scoring:
	    print '[+] scoring each new input'
	else:
	    callback_start_scoring(len(child_inputs))




	for input in child_inputs:
	    if not callback_scored:
	        os.write(sys.stdout.fileno(), '    %s' % input.filename.split('/')[-1])
	    input.note = score(PARAM['PROGNAME'], PARAM['PROGARG'], input.filename, PARAM['TAINT_STDIN'])
	    #input.note = random_score()
	    if not callback_scored:
	        os.write(sys.stdout.fileno(), '\b' * (len(input.filename.split('/')[-1]) + 4))
	    else:
	        callback_scored(input)
	    
	worklist += child_inputs
	accumlist += child_inputs
	worklist.sort(key=lambda x: x.note)
	#worklist.sort(key=lambda x: x.note, reverse = True)
        #worklist.reverse()
	# this is counter-intuitive, but a lot of blocks are executed on
	# completely wrong images
	if PARAM['PROGNAME'] == '/usr/bin/convert':
	    worklist.reverse()
        
        #session.save(target, PARAM, ninput, worklist)
 
    elapsed = (time.time() - start)
    session.save(target, PARAM, ninput, accumlist)
    #print 'null pointer referenece  %d division by zero %d integer subtract %d int width conversion %d int multiply %d int add %d Paths Explored: %s Feasible Paths: %s Total Constraints: %s Actual Constraints: %s Time Taken: %s Valgrind Time: %s'\
     #     % (countnull,  countdiv,  countintsub, countintwidth32to16+countintwidth32to8+countintget+ countintwidthnot32, countintmulu+countintmulsigned,  countintaddu+countintaddsigned, paths,ninput - current,totalcon,pathssub,round(elapsed,2),round(querytime,2))
    print 'Paths Explored: %s Feasible Paths: %s Total Constraints: %s Actual Constraints: %s Time Taken: %s Valgrind Time: %s'\
         % (paths,ninput - current,totalcon,pathssub,round(elapsed,2),round(querytime,2))
    
def usage():
    
    print 'Usage: %s <parameter name>' % sys.argv[0]
    print '  -h --help\t\t\tshow summary of options'
    print '  -c --config\t\t\tconfiguration file'
    print '  -o --subsumption\t\tactivate constraint subsumption'
    print '  -s --session\t\t\tload saved session if present'
    print '  -l --last [vg_output_i.txt]\tdebug on last valgrind output'
    print '  -v --verif\t\t\tverify that constraints are coherent'
    print  '  -i --int [True]'
    print  '  -d --div [True]'
    print  '  -n --null [True]'
    print  '  -x --interactvie [True]'
    sys.exit(0)
            
            
if __name__ == '__main__':
    global check_int
    global check_null
    global check_div
    global interactive
    global debug
    global faulty_inputs
    

    
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hcsl:ovindx', ['help', 'config', 'session', 'last', 'subsumption', 'verif', 'int', 'null', 'div', 'interactive'])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(-1)
        
    if len(args) != 1:
        usage()
        sys.exit(-1)
    
    configfile = 'fuzz/settings.cfg'
    worklist               = None
    DEBUG_LAST             = False
    VERIF_SOLVABLE         = False
    CONSTRAINT_SUBSUMPTION = False
    USE_ACCUM = False
    check_int=False
    check_null=False
    check_div=False
    interactive=False
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit(0)
        elif o in ('-c', '--config'):
            configfile = args[0]
        elif o in ('-s', '--session'):
	    PARAM = get_config(configfile, args[0])
            (name,ext) = PARAM['PROGNAME'].split('.') 
	    PARAM['PROGNAME'] = name +'_cva' + ext
            PARAM, ninput, worklist = session.load(args[0])
            USE_ACCUM = True
            if not worklist:
                print 'Fuzzing done'
                sys.exit(0)
        elif o in ('-l', '--last'):
            DEBUG_LAST = a
        elif o in ('-o', '--subsumption'):
            CONSTRAINT_SUBSUMPTION = True
        elif o in ('-v', '--verif'):
            VERIF_SOLVABLE = True
        elif o in ('-i', 'int'):
            check_int= True
        elif o in ('-n', 'null'):
            check_null= True
        elif o in ('-d', 'div'):
            check_div= True
        elif o in ('-x', 'interactive'):
            interactive= True
        else:
            assert False, 'unhandled option'
            
    target = args[0]
    elapsed = 0
    querytime = 0
    paths = 0
    pathssub = 0 
    start = time.time()
    totalcon = 0
    cva_constraints = {}
    cva_paths = {}
    debug=False
    if not worklist:
        PARAM = get_config(configfile, target)
        ninput = PARAM.get('N', 0)
        input_seed = Input(0, PARAM['INPUT_FILE'], PARAM.get('MIN_BOUND', 0))
        worklist = [ input_seed ]
        faulty_inputs = '/tmp/faulty_inputs_%d.txt' % os.getpid()
        fp = open(faulty_inputs, 'w')
        file_print='Faulty inputs for program %s are in the fallowing files: \n'%PARAM['PROGNAME']
        fp.write( file_print)   
        fp.close()
    search(target, worklist, [ None ] * 10)
