#coding=utf-8
import tracer
import angr 
import os
import sys


if len(sys.argv)<2:
	print "please give an input"
	sys.exit(1)

t=tracer.Tracer('./vul',sys.argv[1])
branches=t.next_branch()
while len(branches.active) >0 and t.bb_cnt <len (t.trace):
	prev_addr =branches.missed[0].addr_trace[-1]
	for path in branches.missed:
		if path.state.satisfiable():
			t_pos=path.state.posix.files[0].pos()
			path.state.posix.files[0].seek[0]
			gen=path.state.posix.read_from(0, t_pos)
			gen=path.state.se.any_str(gen)
			path.state.posix.files[0].seek(t_pos)
			print("gen %s | [%s]" % (gen, gen.encode('hex')))
			break
	branches=t.next_branch()	
