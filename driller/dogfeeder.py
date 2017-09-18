import thread
import time
import os

def feed_dog(moduleMark, freq, FoodDir):
    foodCache = ''
    while True:
        # construct food
        try:
            food = moduleMark + '-' + str(time.time())#hashlib.md5(str(datetime.datetime.now())).hexdigest()
            food = os.path.join(FoodDir, food)
            # feed dog now
            if foodCache == '':
                with open(food, 'w'):
                    pass
            else:
                os.rename(foodCache, food)
            foodCache = food
    #         print ("feed the dog,the food is %s"%food)
            time.sleep(freq)
        except Exception as e:
            continue   

class FeedDog:
    """
    Feed the watch dog every * seconds.
    arg1: module name as defined in ModuleName
    arg2: feed frequency
    arg3: food directory
    return: none
    """
    def __init__(self, _moduleName, _freq, _foodDir):

        self._moduleMark = _moduleName
        self._freq       = _freq
        self._foodDir    = _foodDir

    def start(self):
        thread.start_new_thread(feed_dog, (self._moduleMark, self._freq, self._foodDir))

if __name__ == "__main__":
    fd = FeedDog('verifierH', 5, '.')
    fd.start()

    time.sleep(30)

