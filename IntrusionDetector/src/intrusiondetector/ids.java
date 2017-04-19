package intrusiondetector;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Hashtable;
import java.util.regex.Pattern;  
import org.jnetpcap.Pcap;   
import org.jnetpcap.packet.JPacket;  
import org.jnetpcap.packet.JPacketHandler;  
import org.jnetpcap.protocol.tcpip.Tcp;   
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

/* Aaron McCarthy
 * 
 */

public class ids {
    
    private static Boolean state;                   //True = stateless False = stateful
    private static Boolean proto;                   //True = TCP False = UDP 
    private static String host;
    private static int hostPort = -1;                    // -1 = any
    private static final Hashtable<Integer, String> tfHost = new Hashtable<>(); //stores to/from_host strings
    private static boolean fromHostFirst = false;                               // True if from_host is first in .txt file
    private static int attackerPort = -1;               // -1 = any
    private static int attacker;                    //wait on email reply assume always any until then
    private static int numToFind = 0;               //number of fields to find in pcap before a warning is thrown
    private static int numFound = 0;               //number of fields found
    private static String[] badPacs;                //packets found with violations in them
    
    private static String[][] streamList = new String[1000][1000];           //list of all packets exchanged between host and all sender/reciever pairs
    private static int numCon = 1;                                         //number of connections in list
    
    private static final Pattern hostP = Pattern.compile("host=(\\d*\\.\\d*\\.\\d*\\.\\d*)");
    private static final Pattern portP = Pattern.compile("host_port=(\\d{1,5})");
    private static final Pattern attackerPortP = Pattern.compile("attacker_port=(\\d{1,5})");
    private static final Pattern toHostP = Pattern.compile("to_host=\"((.*?))\"");
    private static final Pattern fromHostP = Pattern.compile("from_host=\"((.*?))\"");
    private static final Pattern protoP = Pattern.compile("proto=(tcp|udp)");
    private static final Pattern typeP = Pattern.compile("type=(s.*)");
     
    
    public static void main(String[] args) throws IOException {
        
        System.out.println("DISCLAIMER: plaintextPOP must be run as stateless");
        System.out.println("DISCLAIMER: Getting jnetpcap to work was difficult, I'm not sure how well it will work on other machines");
        
        String fileName = "trace3.pcap";   //Replace with command line Args
        String policyFileName = "blameAttac62.txt";     //Replace with command line Args
        
        final StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(fileName, errbuf);
        if (pcap == null) {  
            System.err.println(errbuf); 
            return;  
        }
        
        BufferedReader policyBR = getBR(policyFileName);
        setPolicy(policyBR);
        
        
        if(state){
            //stateless(pcap, errbuf); was going to put this in its own method but jnetpcap wont let me
            pcap.loop(-1, new JPacketHandler<StringBuilder>() {                 //loop thu all the pkts
            
                final Tcp tcp = new Tcp();
                final Udp udp = new Udp();
                @Override
                public void nextPacket(JPacket packet, StringBuilder errbuf) {  
                    
                    if(proto){  //looking for tcp
                        if ((packet.hasHeader(tcp) && (tcp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1))               //if tcp and sent from attacker to host
                                || (packet.hasHeader(tcp) && (tcp.destination() == attackerPort || attackerPort == -1) && (tcp.source() == hostPort || hostPort == -1))) {      //if tcp and sent from host to attacker

                            try {
                                
                                byte[] content = tcp.getPayload();
                                String contentStr = new String(content, "UTF-8");
                                switch(numFound){
                                    case 0:
                                        Pattern p0 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m0 = p0.matcher(contentStr);
                                        if (m0.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 1:
                                        Pattern p1 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m1 = p1.matcher(contentStr);
                                        if (m1.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 2:
                                        Pattern p2 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m2 = p2.matcher(contentStr);
                                        if (m2.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 3:
                                        Pattern p3 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m3 = p3.matcher(contentStr);
                                        if (m3.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 4:
                                        Pattern p4 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m4 = p4.matcher(contentStr);
                                        if (m4.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                }
                                
                            } catch (UnsupportedEncodingException ex) {
                                Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                    }
                    else{ //same as if(proto) except with udp
                        if ((packet.hasHeader(udp) && (udp.destination() == hostPort || hostPort == -1) && ( udp.source() == attackerPort || attackerPort == -1))               //if udp and sent from attacker to host
                                || (packet.hasHeader(udp) && (udp.destination() == attackerPort || attackerPort == -1) && (udp.source() == hostPort || hostPort == -1))) {      //if udp and sent from host to attacker

                            try {
                                
                                byte[] content = udp.getPayload();
                                String contentStr = new String(content, "UTF-8");
                                switch(numFound){
                                    case 0:
                                        Pattern p0 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m0 = p0.matcher(contentStr);
                                        if (m0.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 1:
                                        Pattern p1 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m1 = p1.matcher(contentStr);
                                        if (m1.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 2:
                                        Pattern p2 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m2 = p2.matcher(contentStr);
                                        if (m2.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 3:
                                        Pattern p3 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m3 = p3.matcher(contentStr);
                                        if (m3.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                    case 4:
                                        Pattern p4 = Pattern.compile(tfHost.get(numFound));
                                        Matcher m4 = p4.matcher(contentStr);
                                        if (m4.find()) {
                                            
                                            badPacs[numFound] = contentStr;
                                            numFound++;
                                            if(numFound == numToFind){
                                                warn();
                                                numFound = 0;
                                            }
                                        }
                                        break;
                                }
                                
                            } catch (UnsupportedEncodingException ex) {
                                Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                    }
                }  
            }, errbuf); 
        }
        else{ //stateful();
            pcap.loop(-1, new JPacketHandler<StringBuilder>() {                 //loop thu all the pkts
            
                final Tcp tcp = new Tcp();
                final Udp udp = new Udp();
                final Ip4 ip  = new Ip4();
                @Override
                //streamList [streamID][str of payload]
                public void nextPacket(JPacket packet, StringBuilder errbuf) {  

                        if ((packet.hasHeader(tcp) && (tcp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1))               //if tcp and sent from attacker to host
                                || (packet.hasHeader(tcp) && (tcp.destination() == attackerPort || attackerPort == -1) && (tcp.source() == hostPort || hostPort == -1))){
                            
                            String streamID = Integer.toString(tcp.hashCode());
                            
                            for (int i = 0; i < numCon; i++) { //builds streamList keeps track of all payloads of packets seperated by who sent them to the host
                                if(i == numCon - 1){ try {
                                    //gone through list without finding streamID of packet
                                    streamList[i][0] = streamID;
                                    streamList[i][1] = new String(tcp.getPayload(), "UTF-8");
                                    numCon++;
                                    } catch (UnsupportedEncodingException ex) {
                                        Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                                    }
                                    break;
                                }
                                else if(streamList[i][0].equals(streamID)){ //put payload in next spot in this streamID's row
                                    for (int j = 0; j < 500; j++) {
                                        if(streamList[i][j] == null){ try {
                                                streamList[i][j] = new String(tcp.getPayload(), "UTF-8");
                                            } catch (UnsupportedEncodingException ex) {
                                                Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                                            }
                                            break;
                                         }
                                    }
                                    break;
                                }
                            
                            }
                            
                        }
                }
            }, errbuf);
            
            Pattern p0 = Pattern.compile(tfHost.get(0));
            StringBuilder streamLoad = new StringBuilder();
            for (int i = 0; i < streamList.length; i++) { ////complies all packet in streamlist into streamload
                if(streamList[i][0] == null ){
                    break;
                } 
                for (int j = 0; j < streamList.length; j++) {
                    if(streamList[i][j] == null ){
                        break;
                    }
                    streamLoad.append(streamList[i][j]);
                }
            }
            
            Matcher m0 = p0.matcher(streamLoad.toString());
            if(m0.find()){
                badPacs[0] = streamLoad.toString();
                warn();
            }
        }
    }
        
    ///sets all policy parameter instance vars
    public static void setPolicy(BufferedReader br) throws IOException{
        
        String line = br.readLine();
        do{
            Matcher hostM = hostP.matcher(line);
            Matcher typeM = typeP.matcher(line);
            Matcher protoM = protoP.matcher(line);
            Matcher portM = portP.matcher(line);
            Matcher attackerPortM = attackerPortP.matcher(line);
            Matcher toHostM = toHostP.matcher(line);
            Matcher fromHostM = fromHostP.matcher(line);
            
            if (hostM.find()) {
                host = hostM.group(1);
            }
            
            if (typeM.find()) {
                if(typeM.group(1).equals("stateless")){
                    state = true;
                }
                else{
                    state = false;
                }
            }
            
            if (portM.find()) {
                hostPort = Integer.parseInt(portM.group(1));
            }
            
            if (attackerPortM.find()) {
                attackerPort = Integer.parseInt(attackerPortM.group(1));
            }
            
            if (toHostM.find()) {
                tfHost.put(numToFind, toHostM.group(1));
                numToFind++;
            }
            
            if (fromHostM.find()) {
                tfHost.put(numToFind, fromHostM.group(1));
                if(numToFind == 0){
                    fromHostFirst = true;
                }
                numToFind++;
            }
            
            if (protoM.find()) {
                if(protoM.group(1).equals("tcp")){
                    proto = true;
                }
                else{
                    proto = false;
                }
            }
           
            line = br.readLine();
        
        }while(line != null);
        
        badPacs = new String[numToFind];            //creates badPacs tohold correct number of packets
        System.out.println("type: " + state );
        System.out.println("proto: " + proto);
        System.out.println("host: " + host);
        System.out.println("host_port: " + hostPort);
        System.out.println("attacker_port: " + attackerPort);
        if(fromHostFirst){
            for (int i = 0; i < numToFind; i++){
                if(i % 2 == 0){
                    System.out.println("from_host: " + tfHost.get(i));
                }
                else{
                    System.out.println("to_host: " + tfHost.get(i));
                }
            }
        }
        else{
            for (int i = 0; i < numToFind; i++){
                if(i % 2 != 0){
                    System.out.println("from_host: " + tfHost.get(i));
                }
                else{
                    System.out.println("to_host: " + tfHost.get(i));
                }
            }
        }   
    }
    
    public static BufferedReader getBR(String fileName){
        
        BufferedReader reader = null;
        try {
            File f = new File(fileName);
            reader = new BufferedReader(new FileReader(f));
            return reader;
        } catch (FileNotFoundException ex) {
            Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            return reader;
        }
    }
    
    public static void warn(){
        System.out.println("WARNING -- Possible threat in the following packets: ");
        for (int i = 0; i < badPacs.length; i++) {
            System.out.println("-------- Payload of Packet --------");
            System.out.println(badPacs[i]);
        }
    }
    
    
}