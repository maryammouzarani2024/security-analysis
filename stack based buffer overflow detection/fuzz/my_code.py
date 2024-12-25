             #bof detection
#                    totalcon=0
#                    constraints=[]
#                    stp = STP()
#                    threshold = 0                                    
#                    callback_start_constraint_solver = callbacks[0]
#                    callback_constraint_solved = callbacks[1]
#                    callback_start_constraint_analyser = callbacks[2]
#                    callback_constraint_analysed = callbacks[3]
#                    callback_start_expander = callbacks[4]
#                    callback_expanded = callbacks[5]
#                    j=0
#                    if len(pc)>0:
#                        for (c, taken) in pc:
#                            #print c,'   ',taken 
#                            if not taken:
#                                c = 'Not1(%s)' % c
#                            expr = parse_expr(c)
#                            constraints = contraint_subsumption(constraints, expr, stp) # is input.bound still consistent ?
#                            stp.first_cmp = True # XXX - dirty
#                            if not callback_constraint_analysed:
#                                os.write(sys.stdout.fileno(), '%s%d' % ('\b' * len(str(j - 1)), j))
#                            else:
#                                callback_constraint_analysed()
#                            j += 1
#                        
#                        totalcon += len(pc)
#                         
#                        if len(constraints) != len(pc):
#                            print '    * %d path constraints (thanks to constraint subsumption)' % len(constraints)
#                            pathssub += len(constraints)
#                        
#                        # all queries are computed, there will not be change anymore, so we can
#                        # safely create the constraints
#                        loop=-1
#                                        
#                        for c in constraints:
#                            c['stp'] = stp.query[c.pop('n')]
#                        stp.query = []
#                        #we have changed input.bound to zero for test
#
#                        input.bound=0
#                        if input.bound > 0:
#                            # XXX - we should reuse previous stp.query
#                            for j in range(0, input.bound):
#                               if vul[j]=='dep':
#                                stp.query = [ constraints[j]['stp'] ]
#                            stp.negate(len(stp.query) - 1)
#                        
#                        if callback_start_constraint_solver:
#                            callback_start_constraint_solver(len(constraints) - input.bound)
#                        #CVA for infeasible paths    
#                        #infeasible_constraints = []                    
#                        # solve constraints
#                        for j in range(input.bound, len(constraints)):
#                            if not callback_constraint_solved:
#                                print '    * solving constraints [0:%d]' % j
#                            
#                            value = constraints[j]['stp'].pp()
#                            #print value
#                            if stp.query:
#                                stp.negate(len(stp.query) - 1)
#                            
#                                if DEBUG_LAST:
#                                    print '     ', constraints[j-1]['expr'].pp()
#                                    print '     ', constraints[j-1]['stp'].pp()
#                                if DEBUG_LAST or VERIF_SOLVABLE:
#                                    stp.execute()
#                                    if not stp.interpret():
#                                        stp.query.pop()
#                                        print '    ! unsolvable constraint, skipping it !'
#                                        sys.exit(0)
#                                        if callback_constraint_solved:
#                                            callback_constraint_solved(None)
#                                        break
#                            
#                            #print '***', constraints[j]['stp'].pp()
#                            
#                            stp.query += [ constraints[j]['stp'] ]
#                            stp.negate(len(stp.query) - 1)
#                            #start = time.time()
#                            loop=j
#
#                                
#                        if loop== pc_counter:
#                                stp.execute()

                #bof detection
        
