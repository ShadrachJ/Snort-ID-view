# Snort-ID-view
File to read through web traffic and display it in a convenient way, while providing relevant information. 
In order to use, download both the reader.java file and the snortids text file. Copy the name of the text file as a path (shift + right click, copy as path) and past that text in the main method of reader java in the buffered reader line which currently has a file on shad's desktop. Change all \ to / and you're done. When compiled, the code will allow you to display useful statistics for a particular ID, search by ID, display general stats, or show all ID's for a given time. 


Currently the code is inflexible, only working for id's in the format presented (which is common of the snort format). Possible fix for this would be the use of wildcards or a switch to formatting date/time to a data type which can hold them (possibly from an outside library). As it stands the code was a personal challenge using only vanilla java.
