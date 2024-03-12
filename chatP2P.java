import java.io.*;
import java.net.*;

class Peer {

    int port;

    Peer () {
        try {
            System.out.print("Enter port for this Peer: ");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            port = Integer.parseInt(reader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    class Sender extends Thread {

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("[+] Sender created.");
                System.out.println("[!] Enter destination host: "); // Modificado para solicitar o endereço IP do host
                String destHost = in.readLine(); // Agora solicitamos o endereço IP

                System.out.println("Enter destination port: ");
                int destPort = Integer.parseInt(in.readLine());

                Socket s = new Socket(destHost, destPort);
                //DataInputStream BroadcastInput = new DataInputStream(s.getInputStream());
                //DataOutputStream BroadcastOutput = new DataOutputStream(s.getOutputStream());
                DataOutputStream Broadcast = new DataOutputStream(s.getOutputStream());

                while (true) {
                    System.out.print("> ");
                    String message = in.readLine();

                    if (message.isEmpty()) {
                        // ignora empty spaces
                    }
                    else if (message.equalsIgnoreCase("!panic")) {

                        // Panic Message
                        // Força o peer a fechar o socket

                        System.out.println("Sending panic message...");
                        Broadcast.writeUTF(message);
                        s.close();
                        break;

                    } else {
                        Broadcast.writeUTF(message);
                        System.out.println("Message sent");
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    class Receiver extends Thread {

        int port;
        ServerSocket ss;

        Receiver(int port) {
            this.port = port;
        }

        public void run() {
            try {
                ss = new ServerSocket(port);
                System.out.println("[+] Receiver created.");

                Socket s = ss.accept();
                System.out.println("[!] Client connected");

                // DataInputStream BroadcastInput = new DataInputStream(s.getInputStream());
                // DataOutputStream BroadcastOutput = new DataOutputStream(s.getOutputStream());
                DataInputStream Broadcast = new DataInputStream(s.getInputStream());


                while (true) {
                    String message = Broadcast.readUTF();
                    System.out.println("Peer: " + message);
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void newPeer() throws InterruptedException {
        Sender s = new Sender();
        Receiver r = new Receiver(port);

        s.start();
        r.start();

        s.join();
        r.join();
    }

    public static void main(String[] args) throws InterruptedException {
        Peer p = new Peer();
        try {
            System.out.println("[+] New peer created.");
            p.newPeer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}