import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
import csv


def draw(expno):
	
	file='exp' + expno + '_stats.dat'
	with open(file) as csvfile:
		readCSV = csv.reader(csvfile, delimiter='~')
		host = []
		traffic = []
		for row in readCSV:
			traffic.append(int(row[1]))
			host.append(int(row[0]))
		print traffic
		print host
		y_pos=np.arange(len(host))
		plt.bar(y_pos, traffic, align='center', alpha=0.5)
		plt.xticks(y_pos, host)

draw('1')

plt.ylabel("traffic")
plt.xlabel("host")
plt.savefig('RR_traffic_load.pdf')
plt.title('Round Robin');
plt.show()
