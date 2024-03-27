import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

class UserAuthentication {
    private HashMap<String, String> users; // Mapeia o username para a senha (hash)

    UserAuthentication() {
        users = new HashMap<>();
        loadUsersFromFile("config/users.dat");
    }

    private void loadUsersFromFile(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 2) {
                    users.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void saveUsersToFile(String filePath) {
        try (PrintWriter pw = new PrintWriter(filePath)) {
            for (String username : users.keySet()) {
                pw.println(username + "," + users.get(username));
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public boolean authenticate(String username, String password) {
        if (users.containsKey(username)) {
            String hashedPassword = hashPassword(password);
            return hashedPassword.equals(users.get(username));
        }
        return false;
    }

    public boolean addUser(String username, String password) {
        if (!users.containsKey(username)) {
            String hashedPassword = hashPassword(password);
            users.put(username, hashedPassword);
            saveUsersToFile("config/users.dat");
            return true;
        }
        return false;
    }

    // Hash MD5 - Cifra Fraca
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}

class Peer {
    int localPort;
    int remotePort;
    String remoteHost;
    boolean connected;
    BufferedWriter logWriter;
    UserAuthentication auth;

    Peer(String remoteHost, int localPort, int remotePort) {
        this.remoteHost = remoteHost;
        this.localPort = localPort;
        this.remotePort = remotePort;
        this.connected = false;

        // Obtém o diretório atual do users
        String currentDir = System.getProperty("user.dir");

        // Cria a pasta "logs" no diretório atual, se ela não existir
        File logsDir = new File(currentDir + File.separator + "logs");
        if (!logsDir.exists()) {
            logsDir.mkdirs();
        }

        try {
            // Cria o BufferedWriter para escrever no arquivo de log
            String timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
            String logFileName = currentDir + File.separator + "logs" + File.separator + remoteHost + "_" + timeStamp + ".log";
            File logFile = new File(logFileName);
            logFile.createNewFile();
            logWriter = new BufferedWriter(new FileWriter(logFile));
        } catch (IOException e) {
            e.printStackTrace();
        }

        auth = new UserAuthentication();
    }

    public void printHelp() {
        System.out.println("------------------------------------------------------------");
        System.out.println("Available commands:\n");
        System.out.println("!listlogs - List all available log files");
        System.out.println("!readlog <logFileName> - Read the contents of a log file");
        System.out.println("!help - Display this help message");
        System.out.println("!panic - Send a panic message to close the connection");
        System.out.println("------------------------------------------------------------");
    }

    public void registerUser() throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter a username: ");
        String username = reader.readLine();

        System.out.println("Enter a password: ");
        String password = reader.readLine();

        if (auth.addUser(username, password)) {
            System.out.println("User registered successfully.");
        } else {
            System.out.println("Username already exists. Please choose a different username.");
        }
    }

    public void startPeer(String username) throws InterruptedException {
        Sender s = new Sender(username);
        Receiver r = new Receiver(localPort, 5000); // timeout em 5000 ms (5 secs)

        int retryC = 0;
        while (retryC < 3) {
            try {
                s.start();
                r.start();

                s.join();
                r.join();
                break;
            } catch (Exception e) {
                System.out.println("retry " + e);
                retryC++;
            }
        }
    }


    class Sender extends Thread {
        String username;

        Sender(String username) {
            this.username = username;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                //System.out.println("[+] Sender created.");

                Socket s = null;
                DataOutputStream broadcast = null;
                boolean connected = false;

                while (!connected) {
                    try {
                        s = new Socket(remoteHost, remotePort);
                        broadcast = new DataOutputStream(s.getOutputStream());
                        connected = true;
                    } catch (ConnectException e) {
                        //System.out.println("[DEBUG] ERROR: " + e);
                        System.out.println("[-] Connection refused: Unable to connect to the remote host. Retrying...");
                        Thread.sleep(1000); // Espera 1 sec antes de tentar novamente
                    }
                }

                while (true) {
                    System.out.print("> ");
                    String message = in.readLine();

                    if (message.isEmpty()) {
                        // ignora empty spaces
                    } else if (message.equalsIgnoreCase("!panic")) {

                        // Panic Message
                        // Força o peer a fechar o socket
                        System.out.println("Sending panic message...");
                        broadcast.writeUTF(message);
                        s.close();
                        break;

                    } else if (message.equalsIgnoreCase("!listlogs")) {
                        listLogs();
                    } else if (message.startsWith("!readlog")) {

                        String[] parts = message.split(" ");
                        if (parts.length == 2) {
                            readLog(parts[1]);
                        } else {
                            System.out.println("Usage: !readlog <logFileName>");
                        }

                    } else if (message.equalsIgnoreCase("!help")) {
                        printHelp();
                    } else {
                        // Dá broadcast do nome do user junto com a mensagem
                        broadcast.writeUTF(username + ": " + message);
                        System.out.println("Message sent");

                        // Escreve a mensagem enviada no arquivo de log
                        logWriter.write("Sent: " + message + "\n");
                        logWriter.flush();
                    }
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }
    }


    class Receiver extends Thread {
        ServerSocket ss;
        BufferedWriter logWriter;
        boolean connected;

        Receiver(int port, int timeout) {
            try {
                ss = new ServerSocket(port);
                connected = false;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void run() {
            while (true) { // Loop até infinito e mais além para continuar a aceitar conexões
                try {
                    Socket s = ss.accept();
                    System.out.println("[+] Client connected");

                    DataInputStream broadcast = new DataInputStream(s.getInputStream());
                    connected = true;

                    while (true) {
                        String message = broadcast.readUTF();
                        System.out.println(message);

                        // Guarda a mensagem recebida no ficheiro de log
                        if (logWriter != null) {
                            logWriter.write("Received: " + message + "\n");
                            logWriter.flush();
                        }
                    }

                } catch (SocketTimeoutException e) {
                    // Não faz nada se ocorrer um timeout
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }


    public void listLogs() {
        File logsDir = new File("logs");
        if (logsDir.exists() && logsDir.isDirectory()) {
            File[] logFiles = logsDir.listFiles();
            System.out.println("Available log files:");
            for (File file : logFiles) {
                if (file.isFile()) {
                    System.out.println(file.getName());
                }
            }
        } else {
            System.out.println("No log files found.");
        }
    }

    // Lê o os logs do cliente
    // Vulnerável a Path traversal Attack
    // PoC: !readlogs ../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd
    public void readLog(String logFileName) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("logs" + File.separator + logFileName));
            String line;
            System.out.println("Contents of " + logFileName + ":");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (IOException e) {
            System.out.println("Error reading log file: " + e.getMessage());
        }
    }
}

public class chatP2P {
    public static void main(String[] args) throws InterruptedException {
        if (args.length != 3) {
            System.out.println("Usage: Peer <host> <localPort> <remotePort>");
            return;
        }

        String remoteHost = args[0];
        int localPort = Integer.parseInt(args[1]);
        int remotePort = Integer.parseInt(args[2]);

        Peer p = new Peer(remoteHost, localPort, remotePort);

        try {
            System.out.println("[+] New peer created.");

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Do you want to register as a new user? (yes/no): ");
            String registerChoice = reader.readLine();

            if (registerChoice.equalsIgnoreCase("yes")) {
                p.registerUser();
            }

            System.out.println("Enter your username: ");
            String username = reader.readLine();
            System.out.println("Enter your password: ");
            String password = reader.readLine();

            if (!p.auth.authenticate(username, password)) {
                System.out.println("Invalid username or password.");
                return;
            }

            System.out.println("[!] Waiting for a remote peer connection... [!]");
            p.startPeer(username);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}