package intrusiondetector;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;  
import java.util.Hashtable;
import java.util.Map;  
import java.util.Scanner;
import java.util.regex.Pattern;  
import org.jnetpcap.Pcap;   
import org.jnetpcap.packet.JPacket;  
import org.jnetpcap.packet.JPacketHandler;  
import org.jnetpcap.protocol.tcpip.Tcp;   
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.format.FormatUtils;

/* Aaron McCarthy
 * 
 */

public class ids {
    
    private static Boolean state;                   //True = stateless False = stateful
    private static Boolean proto;                   //True = TCP False = UDP 
    private static String host;
    private static String attackType;
    private static int hostPort;
    
    private static String toHost;
    private static int attacker;                    //wait on email reply assume always any until then
    
    private static Pattern ipRegX = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");  //doesnt test for numbers greater that 256 but thats ok
    private static Pattern portRegX = Pattern.compile("\\d{1,5}");  //doesnt test for numbers greater that 256 but thats ok
    private static Pattern to_hostRegX = Pattern.compile("[\"].*[\"]");  //doesnt test for numbers greater that 256 but thats ok
    
    public static void main(String[] args) throws IOException {
        
        String fileName = "trace1.pcap";   //Replace with command line Args
        
        final StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(fileName, errbuf);
        if (pcap == null) {  
            System.err.println(errbuf); 
            return;  
        }
        
        String policyFileName = "blameAttack1.txt";
        
        
        BufferedReader policyBR = getBR(policyFileName);
        setPolicy(policyBR);
        
        
        
        
        
        
        
        
        
        
        
        
        
//        final String fileName = "lbl-internal.20041004-1305.port002.dump.pcap"; //TODO make this command line
//        final StringBuilder errbuf = new StringBuilder();
//        Pcap pcap = Pcap.openOffline(fileName, errbuf);
//        if (pcap == null) {  
//            System.err.println(errbuf); 
//            return;  
//        }
//        Map<String, Integer> synTable = new HashMap<String, Integer>();           //tables to store num synpkts and ackpkts sent by each ip
//        Hashtable<String, Integer> ackTable = new Hashtable<String, Integer>();
//        
//        pcap.loop(-1, new JPacketHandler<StringBuilder>() {                 //loop thu all the pkts
//            final Tcp tcp = new Tcp();  
//            final Ip4 ip = new Ip4();
//  
//            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
//                
//                if (packet.hasHeader(tcp) && tcp.flags() == 0x002 && packet.hasHeader(ip)) {        try {
//                    //if syn pkt
//                    
//                    InetAddress addr = InetAddress.getByAddress(ip.source());
//                    if(synTable.containsKey(addr.getHostAddress())){             //if ip in table iterate num synpkts
//                        
//                        
//                        synTable.put(addr.getHostAddress(), synTable.get(addr.getHostAddress()) +1);
//                        //System.out.println(ip.sourceToInt());
//                    }
//                    else{                                                   //if ip not in table add and set val to 1
//                        synTable.put(addr.getHostAddress(), 1);
//                        //System.out.println(ip.sourceToInt());
//                    }} catch (UnknownHostException ex) {
//                        Logger.getLogger(scannerfinder.class.getName()).log(Level.SEVERE, null, ex);
//                    }
//                    
//                }
//                else if (packet.hasHeader(tcp) && tcp.flags() == 0x012 && packet.hasHeader(ip)) {        try {
//                    //if synack pkt
//                    InetAddress addr = InetAddress.getByAddress(ip.destination());
//                    if(ackTable.containsKey(addr.getHostAddress())){             //if ip in table iterate num ackpkts 
//                        ackTable.put(addr.getHostAddress(), ackTable.get(addr.getHostAddress()) +1);
//                        //System.out.println(ip.sourceToInt());
//                    }
//                    else{                                                   //if ip not in table add and set val to 1
//                        ackTable.put(addr.getHostAddress(), 1);
//                        //System.out.println(ip.sourceToInt());
//                    }
//                    } catch (UnknownHostException ex) {
//                        Logger.getLogger(scannerfinder.class.getName()).log(Level.SEVERE, null, ex);
//                    }
//                    
//                }
//   
//            }  
//  
//        }, errbuf); 
//        
//    for (String key : synTable.keySet()) {
//        if(!ackTable.containsKey(key) || synTable.get(key) >= 3 * ackTable.get(key) ){
//            System.out.println(key);
//        }
//    }
//  
//        pcap.close();  
  
    
    }
    ///sets all policy parameter instance vars
    public static void setPolicy(BufferedReader br) throws IOException{
        String line;
        do{
            line = br.readLine();
            if(Pattern.matches(line, "type=")){
                if(Pattern.matches(line, "stateless")){
                    state = true;
                }
                else{
                    state = false;
                }
            }
            if(Pattern.matches(line, "proto=")){
                if(Pattern.matches(line, "tcp")){
                    proto = true;
                }
                else{
                    proto = false;
                }
            }
            if(Pattern.matches(line, "host=")){             
                if(Pattern.matches(line, ipRegX.pattern())){                             
                    host = ipRegX.split(line)[0];                           
                }
            }
            if(Pattern.matches(line, "host_port=")){             
                if(Pattern.matches(line, portRegX.pattern())){                             
                    hostPort = Integer.parseInt(portRegX.split(line)[0]);                           
                }
            }
            if(Pattern.matches(line, "to_host=")){             
                if(Pattern.matches(line, to_hostRegX.pattern())){                             
                    toHost = to_hostRegX.split(line)[0];                           
                }
            } 
        }while(!line.isEmpty());
        
        System.out.println("type: " + state );
        System.out.println("proto: " + proto);
        System.out.println("host: " + host);
        System.out.println("host_port: " + hostPort);
        System.out.println("toHost: " + toHost);
        
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
}
                   