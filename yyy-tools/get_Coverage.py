#!/usr/bin/python
import os
import sys
import json as js

# Get the total number of basic blocks by Mcsema
def getKnowBBs():
    return float(sys.argv[4])

# Get touched basic blocks
def getTouchedBBs(lastDir, module_name, processes):
    allTouchedBBs = []
    for i in range(0,processes):
        outputDir = os.path.join(lastDir, str(i))
        print "checking path: %s" % outputDir
        for eachfile in os.listdir(outputDir):
            if eachfile.endswith(".json"):
                jsfile = file(os.path.join(outputDir, eachfile))
                cur_tbs = js.load(jsfile)
                tpBBs = []
                if not cur_tbs.has_key(module_name):
                    print "Cannot find target module, skip and continue"
                    continue
                for bb in cur_tbs[module_name]:
                    tpBBs.append(bb[0])
                allTouchedBBs = list(set(allTouchedBBs).union(set(tpBBs)))
                
    res = open("TouchedBB.txt", 'w')
    for bb in allTouchedBBs:
        str_BB = str(hex(bb))
        res.write(str_BB)
        res.write('\n')
    res.close()
    return len(allTouchedBBs)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print "./getCoverage.py \"inputDir\" \"outputDir\" \"processes_name\" "
        exit(-1)
    print "Getting basic coverage for %s" % sys.argv[2]
    inputDir =sys.argv[1]
    outputDir=sys.argv[2]
    
    touBBs = getTouchedBBs(inputDir, outputDir)
    allBBs = getKnowBBs()
    print 'Touched %d basic blocks and the coverage is %s' % (touBBs, format((touBBs/allBBs), '.2%'))
