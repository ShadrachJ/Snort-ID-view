import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Scanner;
/*
 * in the morning i need to go do the search snort run for 116:59:1
 * get each IP used in it and do a full day search with the IP/ID/Time, paste into document
 * 
 */
public class Reader {
	public static boolean checkFormat(String s){
		/*
		 * checks to see if a line will contain Time and IP.
		 * Lines with a "/" character at index 2 will always contain
		 * time, source IP, and destination IP.
		 */
		boolean isCorrect = false;
		if(s.length() >=14){
			if(s.charAt(2)=='/'){
					isCorrect = true;
				}
			}
		return isCorrect;
	}
	public static String initTime(String s){
		/*
		 * returns a string holding the time found from a String passed to it.
		 * should only be used AFTER checkFormat has returned true to validate 
		 * the substring(6,14) will not return out of bounds.
		 */
		String time = s.substring(6, 14);
		return time;
    }
	public static String adjustTime(String time){
		/*
		 * this method is meant to be called on behalf of a String which holds time in HH:MM:SS format
		 * when called it will disect string into Int values, increment as neccessary, and then return the updated
		 * incremented string.
		 */
		String updateTime = "";
		int hour =Integer.parseInt(time.substring(0, 2));
		int minute = Integer.parseInt(time.substring(3, 5));
		int second = Integer.parseInt(time.substring(6, 8));
		if(second < 60){
			second++;
			if(second==60){
				second=0;
				minute++;
				if(minute==60){
						minute=0;
						hour++;
						if(hour>12){
							hour=1;
						}
				}
			}		
		}
		if(hour<10){
			updateTime+= "0" + Integer.toString(hour) + ":";
		}
		else if(hour >= 10){
			updateTime+= Integer.toString(hour)+ ":";
		}
		if(minute<10){
			updateTime+= "0" + Integer.toString(minute)+ ":";
		}
		else if(minute >=10){
			updateTime+=Integer.toString(minute)+ ":";
		}
		if(second<10){
			updateTime+= "0" + Integer.toString(second);
		}
		else if(second >=10){
			updateTime+=Integer.toString(second);
		}
		
		return updateTime;
	}
	public static void retrieveSnortIP(ArrayList<String> ar, String snortID, String IP, String time){
		/*
		 * The code below takes the HH:MM:SS format of time
		 * and segments each part into an int value for the
		 * purpose of being incremented before reconstructing
		 * into a string
		 */
		int hour =Integer.parseInt(time.substring(0, 2));
		int minute = Integer.parseInt(time.substring(3, 5));
		int second = Integer.parseInt(time.substring(6, 8));
		int snortCount = 0;
		
		ArrayList<String> snortList = new ArrayList<String>();
		String t ="";
		/*
		 * making sure that a zero is added to the beginning
		 * of a line where needed since the parseInt removes
		 * leading zeroes
		 */
		if(hour<10){
			t+= "0" + Integer.toString(hour) + ":";
		}
		else if(hour >= 10){
			t += Integer.toString(hour)+ ":";
		}
		if(minute<10){
			t+= "0" + Integer.toString(minute)+ ":";
		}
		else if(minute >=10){
			t+=Integer.toString(minute)+ ":";
		}
		if(second<10){
			t+= "0" + Integer.toString(second);
		}
		else if(second >=10){
			t+=Integer.toString(second);
		}
		/*
		 * snortCount is our buffer here, by waiting for
		 * it to reach 2 we can effectively delay the adding
		 * of a String by 2 iterations, which is the amount
		 * needed in order to reach the line paired with an IP
		 * which has our snortID
		 */
		for(String s : ar){
			if(s.contains(snortID)){
				snortCount++;
			}
			else if(snortCount==1){
				snortCount++;
			}
			else if(snortCount==2){
				/*
				 * add line with IP paired with snort ID to list
				 */
				snortList.add(s);
				snortCount=0;
			}
		}
		for(String s : snortList){
			if(s.contains(IP)){//if the line contains our target IP
				for (int i = 0; i<28801; i++){//3600 seconds in 1 hour
					if(s.contains(t)){
						System.out.println(s);
					}
					t=adjustTime(t);
				}
			}
		}
	}
	public static void retrieveSourceIP(ArrayList<String> ar, String IP, String time){
		/*
		 * essentially the same code as retriveSnort, but without
		 * the functionality of pairing to a snortID. The list will instead
		 * just search for an ID and check if that ID is paired to any time 
		 * within on hour of the user input for time. 
		 */
		int hour =Integer.parseInt(time.substring(0, 2));
		int minute = Integer.parseInt(time.substring(3, 5));
		int second = Integer.parseInt(time.substring(6, 8));
		
		String t ="";
		if(hour<10){
			t+= "0" + Integer.toString(hour) + ":";
		}
		else if(hour >= 10){
			t += Integer.toString(hour)+ ":";
		}
		if(minute<10){
			t+= "0" + Integer.toString(minute)+ ":";
		}
		else if(minute >=10){
			t+=Integer.toString(minute)+ ":";
		}
		if(second<10){
			t+= "0" + Integer.toString(second);
		}
		else if(second >=10){
			t+=Integer.toString(second);
		}
		for(String s : ar){
			if(s.contains(IP)){
				for (int i = 0; i<3601; i++){
					if(s.contains(t)){
						System.out.println(s);
					}
					t=adjustTime(t);
				}
				break;
			}
		}
	}
	public static void printSnorts(ArrayList<String> ar){
		/*
		 * prints out all records
		 */
		for(String s : ar){
			System.out.println(s);
		}
	}
	public static void findSnort(ArrayList<String> ar, String snortID){
		/*
		 * searches the array for a target snortID. Prints the ID
		 * if it is found, and will print a message that the ID does 
		 * not exist if no record is returned. The integer value C
		 * is a buffer value, on the pass we find our target we set C 1 and print the line
		 * the next pass through will be an undesired line 100% of the time so we 
		 * increment C until the next pass where we will again print the value.
		 */
		int c = 0;
		boolean found = false;
		for(String s : ar){
			if (s.contains(snortID)){
				found = true;
				c++;
				System.out.println(s);
			}
			else if(c==1){
				c++;
			}
			else if(c==2){
				System.out.println(s);
				System.out.println();
				c = 0;
			}
		}
		if(found==false){
			System.out.println("no record with that snortID exists within the IDList");
		}
	}
	public static void printStatistics(ArrayList<String> ar){
		int c = 0;
		int i = 0;
		String startTime = "";
		String endTime = "";
		
		for(String s : ar){
			if(i==0){
				if(checkFormat(s)){
					startTime=initTime(s);
					i++;
				}	
			}
			if(i > 0){
				if(checkFormat(s)){
					endTime=initTime(s);
				}
			}
			c++;
		}
		System.out.println();
		System.out.println("The time of the first report is " + startTime);
		System.out.println("The time of the second report is " + endTime);
		System.out.println("The amount of reports is " + c/4 );
		System.out.println();
	}
	public static void main(String[] args) throws FileNotFoundException {
		 Scanner testScan = new Scanner(new File("//ronmaiden/Profiles/sjakes/Desktop/SnortIDS-Log.txt"));
		 Scanner sc = new Scanner(System.in);
		 int idsCounter = 0;
		 int userChoice = 1;
		 String snortID = "";
		 String IP = "";
		 String userTime = "";
		
		 ArrayList<String> snortList= new ArrayList<String>();

		 while(testScan.hasNext()){
		  snortList.add(testScan.nextLine());
		 }
		 System.out.println("Please select a choice: \n"
		 		+ " 0 to exit \n"
		 		+ " 1 to search by ID \n"
		 		+ " 2 to display all results \n"
		 		+ " 3 to display statistics \n"
		 		+ " 4 to search by IP and hour \n"
		 		+ " 5 to search by snortID, IP, and hour");
		 userChoice=sc.nextInt();
		
		while (userChoice!=0){
			
			if(userChoice==1){
				System.out.println();
				System.out.println("Please enter a snort ID (format ###:#(#):#");
				snortID=sc.next();
				findSnort(snortList,snortID);
			}
			
			else if(userChoice==2){
				printSnorts(snortList);
			}
		
			else if(userChoice==3){
				printStatistics(snortList);
			}
			else if(userChoice==4){
				System.out.println("Please enter an ip address: ");
				IP = sc.next();
				System.out.println("Please enter in a time (HH:MM:SS). All reports for ip " + IP + " within one hour of the time will be shown." );
				userTime = sc.next();
				retrieveSourceIP(snortList,IP,userTime);
			}
			else if(userChoice==5){
				System.out.println("Please enter a proposed snortID");
				snortID =sc.next();
				System.out.println("Please enter an ip address: ");
				IP = sc.next();
				System.out.println("Please enter in a time (HH:MM:SS). All reports for ip " + IP + " within one hour of the time will be shown." );
				userTime = sc.next();
				retrieveSnortIP(snortList,snortID,IP,userTime);
		 }
			System.out.println();
		    System.out.println("Please select a choice: \n"
				 		+ " 0 to exit \n"
				 		+ " 1 to search by ID \n"
				 		+ " 2 to display all results \n"
				 		+ " 3 to display statistics \n"
				 		+ " 4 to search by IP and hour \n"
				 		+ " 5 to search by snortID, IP, and hour");
			userChoice=sc.nextInt();
		}
		System.out.println("Thanks for using me");
		 testScan.close();
		 sc.close();
	}

}
