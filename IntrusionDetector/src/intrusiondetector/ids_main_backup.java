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

public class ids_main_backup {
    private static Boolean state;                   //True = stateless False = stateful
    private static Boolean proto;                   //True = TCP False = UDP 
    private static String host;
    private static int hostPort = -1;                    // -1 = any
    private static String toHost1 = "";
    private static String fromHost1 = "";
    private static String toHost2 = "";
    private static String fromHost2 = "";
    private static String toHost3 = "";
    private static String fromHost3 = "";
    private static String toHost4 = "";
    private static String fromHost4 = "";
    private static int attackerPort = -1;               // -1 = any
    private static int attacker;                    //wait on email reply assume always any until then
    private static int numToFind = 1;               //number of feilds to find in packet before a warning is thrown
    
    private static Pattern hostP = Pattern.compile("host=(\\d*\\.\\d*\\.\\d*\\.\\d*)");
    private static Pattern portP = Pattern.compile("host_port=(\\d{1,5})");
    private static Pattern attackerPortP = Pattern.compile("attacker_port=(\\d{1,5})");
    private static Pattern toHostP1 = Pattern.compile("to_host=(\"(.*?)\")");
    private static Pattern fromHostP1 = Pattern.compile("from_host=(\"(.*?)\")");
    private static Pattern toHostP2 = Pattern.compile("to_host=(\"(.*?)\")");
    private static Pattern fromHostP2 = Pattern.compile("from_host=(\"(.*?)\")");
    private static Pattern toHostP3 = Pattern.compile("to_host=(\"(.*?)\")");
    private static Pattern fromHostP3 = Pattern.compile("from_host=(\"(.*?)\")");
    private static Pattern toHostP4 = Pattern.compile("to_host=(\"(.*?)\")");
    private static Pattern fromHostP4 = Pattern.compile("from_host=(\"(.*?)\")");
    private static Pattern protoP = Pattern.compile("proto=(tcp|udp)");
    private static Pattern typeP = Pattern.compile("type=(s.*)");
     
    
    public static void main(String[] args) throws IOException {
        
        String fileName = "trace4.pcap";   //Replace with command line Args
        String policyFileName = "plaintextPOP.txt";     //Replace with command line Args
        
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
            //final Ip4 ip = new Ip4();
  
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
                int numFound = 0;
                //make patterns and matchers for all toHosts and fromHosts 
                Pattern toFind1 = Pattern.compile(toHost1);
                Pattern toFind2 = Pattern.compile(fromHost1);
                Pattern toFind3 = Pattern.compile(toHost2);
                Pattern toFind4 = Pattern.compile(fromHost2);
                Pattern toFind5 = Pattern.compile(toHost3);
                Pattern toFind6 = Pattern.compile(fromHost4);
                Pattern toFind7 = Pattern.compile(toHost4);
                Pattern toFind8 = Pattern.compile(fromHost4);
                
                if(proto){  //looking for tcp
                    if (packet.hasHeader(tcp) && (tcp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1)) {        
                        try {
                            byte[] content = tcp.getPayload();
                            String contentStr = new String(content, "UTF-8");
                            
                            Matcher toHost1 = toFind1.matcher(contentStr); 
                            if(!fromHost1.isEmpty()){
                                Matcher fromHost1 = toFind2.matcher(contentStr); 
                            }
                            if(!toHost2.isEmpty()){
                                Matcher toHost2 = toFind3.matcher(contentStr); 
                            }
                            if(!fromHost2.isEmpty()){
                                Matcher fromHost2 = toFind4.matcher(contentStr); 
                            }
                            if(!toHost3.isEmpty()){
                                Matcher toHost3 = toFind5.matcher(contentStr);
                            }
                            if(!fromHost3.isEmpty()){                                
                                Matcher fromHost3 = toFind6.matcher(contentStr); 
                            }
                            if(!toHost4.isEmpty()){
                                Matcher toHost4 = toFind7.matcher(contentStr); 
                            }
                            if(!fromHost4.isEmpty()){
                                Matcher fromHost4 = toFind8.matcher(contentStr);
                            }
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            if(toHost1.find() && true){
                                System.out.println("found host1");
                            }
                            //System.out.println(contentStr);
                            
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
                else{
                    if (packet.hasHeader(udp) && (udp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1)) {
//                        try {
//                            byte[] content = udp.getPayload();
//                            String contentStr = new String(content, "UTF-8");
//                            Pattern toFind = Pattern.compile(toHost1); 
//                            Matcher toHost = toFind.matcher(contentStr);
//                            if(toHost.find()){
//                                System.out.println("WARNING -- Possible threat" + udp.toString());
//                            }
//                        } catch (UnsupportedEncodingException ex) {
//                            Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
//                        }
                    }
                }
            }  
        }, errbuf); 
        }
        else{
            stateful();
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
            Matcher toHostM1 = toHostP1.matcher(line);
            Matcher fromHostM1 = fromHostP1.matcher(line);
            Matcher toHostM2 = toHostP2.matcher(line);
            Matcher fromHostM2 = fromHostP2.matcher(line);
            Matcher toHostM3 = toHostP3.matcher(line);
            Matcher fromHostM3 = fromHostP3.matcher(line);
            Matcher toHostM4 = toHostP4.matcher(line);
            Matcher fromHostM4 = fromHostP4.matcher(line);
            
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
            
            if (toHostM1.find() && toHost1.isEmpty()) {
                toHost1 = toHostM1.group(1);
            }
            else if (toHostM2.find() && toHost2.isEmpty()) {
                toHost2 = toHostM2.group(1);
            }
            else if (toHostM3.find() && toHost3.isEmpty()) {
                toHost3 = toHostM3.group(1);
            }
            else if (toHostM4.find() && toHost4.isEmpty()) {
                toHost4 = toHostM4.group(1);
            }
            
            if (fromHostM1.find() && fromHost1.isEmpty()) {
                fromHost1 = fromHostM1.group(1);
            }
            else if (fromHostM2.find() && fromHost2.isEmpty()) {
                fromHost2 = fromHostM2.group(1);
            }
            else if (fromHostM3.find() && fromHost3.isEmpty()) {
                fromHost3 = fromHostM3.group(1);
            }
            else if (fromHostM4.find() && fromHost4.isEmpty()) {
                fromHost4 = fromHostM4.group(1);
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
        System.out.println("attacker_port: " + attackerPort);
        System.out.println("toHost1: " + toHost1);
        if (!(toHost2.isEmpty())){
            System.out.println("toHost2: " + toHost2);
            numToFind++;
        }
        if (!(toHost3.isEmpty())){
            System.out.println("toHost3: " + toHost3);
            numToFind++;
        }
        if (!(toHost4.isEmpty())){
            System.out.println("toHost4: " + toHost4);
            numToFind++;
        }
        
        if (!(fromHost1.isEmpty())){
            System.out.println("fromHost1: " + fromHost1);
            numToFind++;
        }
        if (!(fromHost2.isEmpty())){
            System.out.println("fromHost4: " + fromHost2);
            numToFind++;
        }
        if (!(fromHost3.isEmpty())){
            System.out.println("fromHost3: " + fromHost3);
            numToFind++;
        }
        if (!(fromHost4.isEmpty())){
            System.out.println("fromHost4: " + fromHost4);
            numToFind++;
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
    
    public static void stateless(Pcap pcap, StringBuilder errbuf){
        
        pcap.loop(-1, new JPacketHandler<StringBuilder>() {                 //loop thu all the pkts
            
            final Tcp tcp = new Tcp();
            final Udp udp = new Udp();
            final Ip4 ip = new Ip4();
  
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
                int numFound = 0;
                if(proto){  //looking for tcp
                    if (packet.hasHeader(tcp) && (tcp.destination() == hostPort || hostPort == -1) && ( tcp.source() == attackerPort || attackerPort == -1)) {        
                        try {
                            byte[] content = tcp.getPayload();
                            String contentStr = new String(content, "UTF-8");
                            //make patterns and matchers for all toHosts and fromHosts
                            Pattern toFind1 = Pattern.compile(toHost1);
                            Pattern toFind2 = Pattern.compile(fromHost1);
                            Pattern toFind3 = Pattern.compile(toHost2);
                            Pattern toFind4 = Pattern.compile(fromHost2);
                            Pattern toFind5 = Pattern.compile(toHost3);
                            Pattern toFind6 = Pattern.compile(fromHost4);
                            Pattern toFind7 = Pattern.compile(toHost4);
                            Pattern toFind8 = Pattern.compile(fromHost4); 
                            Matcher toHost1 = toFind1.matcher(contentStr); 
                            Matcher toHost2 = toFind3.matcher(contentStr); 
                            Matcher toHost3 = toFind5.matcher(contentStr); 
                            Matcher toHost4 = toFind7.matcher(contentStr); 
                            Matcher fromHost1 = toFind2.matcher(contentStr); 
                            Matcher fromHost2 = toFind4.matcher(contentStr); 
                            Matcher fromHost3 = toFind6.matcher(contentStr); 
                            Matcher fromHost4 = toFind8.matcher(contentStr);
                            
                            
                            if(toHost1.find()){
                                
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
                            Pattern toFind = Pattern.compile(toHost1); 
                            Matcher toHost = toFind.matcher(contentStr);
                            if(toHost.find()){
                                System.out.println("WARNING -- Possible threat" + udp.toString());
                            }
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(ids.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
            }  
        }, errbuf); 
    }
    public static void stateful(){
        
    }
    
    public static void warn(String tcp){
        System.out.println("WARNING -- Possible threat" + tcp);
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
  

