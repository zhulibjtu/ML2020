import numpy as np
import random as rd
import matplotlib.pyplot as plt
moneyarray = 100*np.ones(100)
for i in range(17000):
    for j in range(100):
        if moneyarray[j]>0.001:
            moneyarray[j] = moneyarray[j]-1
            winnernumber = np.random.randint(1,101)-1
            moneyarray[winnernumber] = moneyarray[winnernumber] +1

x = np.arange(100)
moneyarray.sort()

plt.figure()
plt.subplot(2,1,1)
plt.bar(x,moneyarray)
plt.subplot(2,1,2)
plt.hist(moneyarray,10)
plt.show()
print(moneyarray)
