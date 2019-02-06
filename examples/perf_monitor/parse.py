
final_list = []
with open("logs/mme.txt") as f:
    for line in f:
        list_line = line.split()
        if (len(list_line) == 0):
            continue
        if (list_line[0] == "#"):
            continue
        if (list_line[1] == "<not"):
            final_list.append(0)
        else:
            final_list.append(float(list_line[1]))

thefile = open('logs/mme_parsed.txt', 'w')
for item in final_list:
    thefile.write("%s\n"%item)
