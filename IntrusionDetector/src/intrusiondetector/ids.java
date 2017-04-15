package intrusiondetector;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
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
    private static String toHost;
    private static int attackerPort = -1;               // -1 = any
    private static int attacker;                    //wait on email reply assume always any until then
    
    private static Pattern hostP = Pattern.compile("host=(\\d*\\.\\d*\\.\\d*\\.\\d*)");
    private static Pattern portP = Pattern.compile("host_port=(\\d{1,5})");
    private static Pattern attackerPortP = Pattern.compile("attacker_port=(\\d{1,5})");
    private static Pattern toHostP = Pattern.compile("to_host=(\"(.*?)\")");
    private static Pattern protoP = Pattern.compile("proto=(tcp|udp)");
    private static Pattern typeP = Pattern.compile("type=(s.*)");
     
    
    public static void main(String[] args) throws IOException {
        
        String fileName = "trace1.pcap";   //Replace with command line Args
        String policyFileName = "blameAttack1.txt";     //Replace with command line Args
        
        final StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(fileName, errbuf);
        if (pcap == null) {  
            System.err.println(errbuf); 
            return;  
        }
        
        BufferedReader policyBR = getBR(policyFileName);
        setPolicy(policyBR);
        
        
        //put into statless() method
        pcap.loop(-1, new JPacketHandler<StringBuilder>() {                 //loop thu all the pkts
            
            final Tcp tcp = new Tcp();
            final Udp udp = new Udp();
            //final Ip4 ip = new Ip4();
  
            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
                
                if(proto){  //looking for tcp
                    if (packet.hasHeader(tcp) && (tcp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1)) {        
                        try {
                            byte[] content = tcp.getPayload();
                            String contentStr = new String(content, "UTF-8");
                            Pattern toFind = Pattern.compile("Now I own your computer"); 
                            Matcher toHost = toFind.matcher(contentStr);
                            if(toHost.find()){
                                System.out.println("WARNING -- Possible threat" + tcp.toString());
                            }
                            //System.out.println(contentStr);
                            
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
                else{
                    if (packet.hasHeader(udp) && (udp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1)) {
                        try {
                            byte[] content = udp.getPayload();
                            String contentStr = new String(content, "UTF-8");
                            Pattern toFind = Pattern.compile(toHost); 
                            Matcher toHost = toFind.matcher(contentStr);
                            
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
            }  
        }, errbuf); 
                
                
        
        
        
        
        
        
        
        
        
  
    
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
                toHost = toHostM.group(1);
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
       
      
////         pcap.loop(-1, new JPacketHandler<StringBuilder>() {                 //loop thu all the pkts
//            
//            final Tcp tcp = new Tcp();
//            final Udp udp = new Udp();
//            final Ip4 ip = new Ip4();
//  
//            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
//                
//                if(proto){  //looking for tcp
//                    if (packet.hasHeader(tcp) && (tcp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1)) {        try {
//                        //if syn pkt
//
//                        InetAddress addr = InetAddress.getByAddress(ip.source());
//                        if(synTable.containsKey(addr.getHostAddress())){             //if ip in table iterate num synpkts
//
//
//                            synTable.put(addr.getHostAddress(), synTable.get(addr.getHostAddress()) +1);
//                            //System.out.println(ip.sourceToInt());
//                        }
//                        else{                                                   //if ip not in table add and set val to 1
//                            synTable.put(addr.getHostAddress(), 1);
//                            //System.out.println(ip.sourceToInt());
//                        }} catch (UnknownHostException ex) {
//                            Logger.getLogger(scannerfinder.class.getName()).log(Level.SEVERE, null, ex);
//                        }
//
//                    }
//                }
//                else{
//                    if (packet.hasHeader(udp) && (udp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1)) {
//                    
//                    }
//                }
//                    
//                
//                
//                
//                
//                
//                
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
//
//
//
//
//
//
//
//
//
//            final String fileName = "lbl-internal.20041004-1305.port002.dump.pcap"; //TODO make this command line
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
  