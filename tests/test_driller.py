#coding=utf-8
import nose #一种单元测试框架
import driller

import logging
l = logging.getLogger("driller.tests.test_driller")

import os
#配置二进制目录
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
def test_drilling_cgc():
    '''
    test drilling on the cgc binary, palindrome.
    '''

    binary = "tests/cgc/sc1_0b32aa01_01" #目标程序
    # fuzzbitmap says every transition is worth satisfying
    d = driller.Driller(os.path.join(bin_location, binary), "AAAA", "\xff"*65535, "whatever~") 
    new_inputs = d.drill() #用来产生新的输入文件
    nose.tools.assert_equal(len(new_inputs), 7)
    # make sure driller produced a new input which hits the easter egg
    nose.tools.assert_true(any(filter(lambda x: x[1].startswith('^'), new_inputs))) #为什么是以 '^'开始?

def run_all():
    functions = globals() # globals 是内置函数,返回当前模块的符号表,字典格式,k是函数名,v是函数对象
    #注意 filter 函数,前一个是函数,后一个是输入(list格式),最后输出是一个过滤后的list,根据第一个的true和false判断留还是删除  ; lambda 函数,':'前是输入,后是输出,
    all_functions = dict(filter( (lambda (k, v): k.startswith('test_')), functions.items()) ) #list中每个是一个(k,v)对象,然后再变成dict
    for f in sorted(all_functions.keys()): # sorted 函数
        if hasattr(all_functions[f], '__call__'): #判断函数对象是否有 __call__ 属性, 这个是object对象的属性,用来判断是否为函数
            all_functions[f]() #call的函数的参数为无,即调用所有'test_*'系列函数

if __name__ == "__main__":
    run_all()
