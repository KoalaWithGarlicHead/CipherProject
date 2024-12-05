import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Objects;

public class EncryptionApp {
    // 定义路径输入字段为类的成员变量
    private static JTextField symmetricKeyPathField;
    private static JTextField publicKeyPathField;
    private static JTextField privateKeyPathField;
    private static JTextField modulusPathField;
    private static JTextField encryptedFilePathField;
    private static JTextField signatureFilePathField;

    public static void main(String[] args) {
        // 创建主窗口
        JFrame frame = new JFrame("加密与签名系统");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 700);
        frame.setLocationRelativeTo(null); // 窗口居中显示
        frame.setLayout(new BorderLayout());

        // 输入类型选择
        JComboBox<String> inputTypeDropdown = new JComboBox<>(new String[]{"String", "File"});
        JTextField inputTextField = new JTextField("请输入字符串...");
        inputTextField.setForeground(Color.GRAY); // 设置提示文本颜色
        inputTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (inputTextField.getText().equals("请输入字符串...")) {
                    inputTextField.setText("");
                    inputTextField.setForeground(Color.BLACK); // 恢复正常文本颜色
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (inputTextField.getText().isEmpty()) {
                    inputTextField.setForeground(Color.GRAY);
                    inputTextField.setText("请输入字符串...");
                }
            }
        });

        inputTextField.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                SwingUtilities.invokeLater(() -> {
                    if (inputTextField.getText().isEmpty() && !inputTextField.isFocusOwner()) {
                        inputTextField.setForeground(Color.GRAY);
                        inputTextField.setText("请输入字符串...");
                    }
                });
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                update();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                update();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                update();
            }
        });



        JButton fileChooserButton = new JButton("选择文件");
        JTextField filePathField = new JTextField();
        filePathField.setEditable(false);

        // 初始设置
        fileChooserButton.setEnabled(false);
        filePathField.setEnabled(false);

        // 算法选择
        JComboBox<String> hashAlgorithmDropdown = new JComboBox<>(new String[]{"MD5", "SHA1"});
        JComboBox<String> encryptionAlgorithmDropdown = new JComboBox<>(new String[]{"AES", "DES"});

        // 对称密钥种子输入
        JTextField keySeedField = new JTextField("123456789"); // 默认种子值

        // 输入区域面板
        JPanel inputPanel = new JPanel(new GridLayout(5, 2, 5, 5));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // 上、左、下、右各10像素的内边距
        inputPanel.add(new JLabel("输入类型:"));
        inputPanel.add(inputTypeDropdown);
        inputPanel.add(new JLabel("输入字符串:"));
        inputPanel.add(inputTextField);
        inputPanel.add(new JLabel("选择文件:"));
        inputPanel.add(fileChooserButton);
        inputPanel.add(new JLabel("文件路径:"));
        inputPanel.add(filePathField);
        inputPanel.add(new JLabel("对称密钥种子:"));
        inputPanel.add(keySeedField);

        // 算法选择面板
        JPanel algorithmPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        algorithmPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // 上、左、下、右各10像素的内边距
        algorithmPanel.add(new JLabel("哈希算法:"));
        algorithmPanel.add(hashAlgorithmDropdown);
        algorithmPanel.add(new JLabel("加密算法:"));
        algorithmPanel.add(encryptionAlgorithmDropdown);

        // 将输入区域和算法选择面板组合
        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.add(inputPanel, BorderLayout.CENTER);
        northPanel.add(algorithmPanel, BorderLayout.SOUTH);

        frame.add(northPanel, BorderLayout.NORTH);

        // 获取当前工作目录
        String currentDir = System.getProperty("user.dir");
        // 指定 files 文件夹路径
        String filesDirPath = currentDir + File.separator + "files";

        // 创建路径输入面板
        JPanel pathPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 初始化路径输入字段
        symmetricKeyPathField = addPathField(pathPanel, gbc, "对称密钥保存路径:", filesDirPath + File.separator + "symmetric.key");
        publicKeyPathField = addPathField(pathPanel, gbc, "公钥保存路径:", filesDirPath + File.separator + "public.key");
        privateKeyPathField = addPathField(pathPanel, gbc, "私钥保存路径:", filesDirPath + File.separator + "private.key");
        modulusPathField = addPathField(pathPanel, gbc, "RSA模数保存路径:", filesDirPath + File.separator + "modulus.key");
        encryptedFilePathField = addPathField(pathPanel, gbc, "加密文件保存路径:", filesDirPath + File.separator + "encrypted.dat");
        signatureFilePathField = addPathField(pathPanel, gbc, "签名文件保存路径:", filesDirPath + File.separator + "signature.sig");

        // 创建一个新的面板来包含路径设置和结果显示区域
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(pathPanel, BorderLayout.NORTH);

        // 结果显示区域
        JTextArea resultTextArea = new JTextArea();
        resultTextArea.setEditable(false);
        resultTextArea.setLineWrap(true);
        resultTextArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(resultTextArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        frame.add(centerPanel, BorderLayout.CENTER);

        // 按钮区域
        JButton executeButton = new JButton("执行加密操作");
        JButton decryptButton = new JButton("解密并验证签名");
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));
        buttonPanel.add(executeButton);
        buttonPanel.add(decryptButton);
        frame.add(buttonPanel, BorderLayout.SOUTH);

        // 显示窗口
        frame.setVisible(true);

        // 文件选择按钮事件
        fileChooserButton.addActionListener(e -> {
            // 创建 JFileChooser，并将默认路径设置为当前工作目录
            JFileChooser fileChooser = new JFileChooser(new File(filesDirPath));
            int returnValue = fileChooser.showOpenDialog(null); // 打开对话框
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile(); // 获取文件
                filePathField.setText(selectedFile.getAbsolutePath()); // 显示文件路径
            }
        });

        // 输入类型切换事件
        inputTypeDropdown.addActionListener(e -> {
            String selectedType = (String) inputTypeDropdown.getSelectedItem();
            if ("String".equals(selectedType)) {
                inputTextField.setEnabled(true);
                fileChooserButton.setEnabled(false);
                filePathField.setEnabled(false);
            } else if ("File".equals(selectedType)) {
                inputTextField.setEnabled(false);
                fileChooserButton.setEnabled(true);
                filePathField.setEnabled(true);
            }
        });

        executeButton.addActionListener(e -> {
            try {
                // 获取用户输入的种子值
                String seedText = keySeedField.getText().trim();
                long seed = seedText.isEmpty() ? 123456789L : Long.parseLong(seedText);

                // 获取输入类型
                String inputType = (String) inputTypeDropdown.getSelectedItem();
                byte[] inputData = EncryptionUtils.getInputData(inputType, inputTextField.getText(),
                        new File(filePathField.getText()));

                // 选择哈希算法
                String hashAlgorithm = (String) hashAlgorithmDropdown.getSelectedItem();
                byte[] hash = hashAlgorithm.equals("MD5") ? MD5.md5(inputData) : SHA1.sha1(inputData);

                // 使用 RSA 生成签名
                RSA rsa = new RSA(); // 生成新的密钥对
                BigInteger signature = EncryptionUtils.sign(hash, rsa);
                BigInteger privateKey = rsa.getPrivateKey();
                BigInteger publicKey = rsa.getPublicKey();
                BigInteger modulus = rsa.getModulus();

                System.out.println("modulus"+modulus);
                System.out.println("publicKey"+publicKey);

                // 加密数据
                String encryptionAlgorithm = (String) encryptionAlgorithmDropdown.getSelectedItem();
                byte[] symmetricKey = encryptionAlgorithm.equals("AES") ? KeyGenerator.generate128BitKey(seed)
                        : KeyGenerator.generate64BitKey(seed);

                // 获取用户指定的路径
                String symmetricKeySavePath = symmetricKeyPathField.getText().trim();
                String publicKeySavePath = publicKeyPathField.getText().trim();
                String privateKeySavePath = privateKeyPathField.getText().trim();
                String modulusSavePath = modulusPathField.getText().trim();
                String encryptedFileSavePath = encryptedFilePathField.getText().trim();
                String signatureFileSavePath = signatureFilePathField.getText().trim();

                try {
                    // 保存密钥并获取保存路径
                    symmetricKeySavePath = saveKeyToFile(symmetricKey, symmetricKeySavePath);
                    publicKeySavePath = saveBigIntegerToFile(publicKey, publicKeySavePath);
                    privateKeySavePath = saveBigIntegerToFile(privateKey, privateKeySavePath);
                    modulusSavePath = saveBigIntegerToFile(modulus, modulusSavePath);

                    // 显示所有密钥文件的保存路径
                    String message = String.format("密钥已成功保存到以下文件：\n对称密钥：%s\n公钥：%s\n私钥：%s\nRSA模数：%s\n",
                            symmetricKeySavePath, publicKeySavePath, privateKeySavePath, modulusSavePath);
                    JOptionPane.showMessageDialog(null, message, "保存成功", JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException e2) {
                    e2.printStackTrace();
                    JOptionPane.showMessageDialog(null, "密钥保存失败：" + e2.getMessage(),
                            "保存失败", JOptionPane.ERROR_MESSAGE);
                }

                byte[] encryptedData = EncryptionUtils.encrypt(encryptionAlgorithm, inputData, symmetricKey);

                // 显示结果（针对字符串输入）
                if (inputType.equals("String")) {
                    resultTextArea.setText(
                            "哈希值: " + EncryptionUtils.byteArrayToHexString(hash) +
                            "\n已通过RSA私钥签名: " + signature +
                            "\n加密数据: " + EncryptionUtils.byteArrayToHexString(encryptedData)
                    );
                }

                // 保存结果到文件（针对文件输入）
                if (inputType.equals("File")) {
                    // 创建输出文件
                    File encryptedOutput = new File(encryptedFileSavePath);
                    File signatureOutput = new File(signatureFileSavePath);

                    // 保存加密结果和签名
                    Files.write(encryptedOutput.toPath(), encryptedData);
                    Files.write(signatureOutput.toPath(), signature.toByteArray());

                    // 提示保存成功
                    resultTextArea.setText(
                            "文件加密与签名已完成！\n" +
                            "加密文件保存为: " + encryptedOutput.getAbsolutePath() + "\n" +
                            "签名文件保存为: " + signatureOutput.getAbsolutePath()
                    );
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "发生错误: " + ex.getMessage());
            }
        });

        decryptButton.addActionListener(e -> {
            try {
                // 获取输入类型
                String inputType = (String) inputTypeDropdown.getSelectedItem();

                // 选择加密算法
                String encryptionAlgorithm = (String) encryptionAlgorithmDropdown.getSelectedItem();

                // 读取对称密钥
                byte[] symmetricKey = readSymmetricKey("symmetric.key");
                if (symmetricKey != null) {
                    System.out.println("对称密钥已成功读取。");
                }

                // 读取公钥
                BigInteger publicKey = readBigIntegerKey("public.key");
                if (publicKey != null) {
                    System.out.println("公钥已成功读取。");
                }

                // 读取模数
                BigInteger modulus = readBigIntegerKey("modulus.key");
                if (modulus != null) {
                    System.out.println("RSA模数已成功读取。");
                }

                if ("String".equals(inputType)) {
                    // 解密字符串
                    String encryptedString = JOptionPane.showInputDialog("请输入加密后的字符串（十六进制）:");
                    if (encryptedString == null || encryptedString.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "未输入加密字符串！");
                        return;
                    }
                    byte[] encryptedData = EncryptionUtils.hexStringToByteArray(encryptedString);

                    // 解密数据
                    byte[] decryptedData = EncryptionUtils.decrypt(encryptionAlgorithm, encryptedData, symmetricKey);

                    // 验证签名
                    String signatureString = JOptionPane.showInputDialog("请输入签名:");
                    if (signatureString == null || signatureString.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "未输入签名！");
                        return;
                    }
                    BigInteger signature = new BigInteger(signatureString);

                    String hashAlgorithm = (String) hashAlgorithmDropdown.getSelectedItem();
                    boolean isValid = EncryptionUtils.verifySignature(signature, decryptedData, new RSA(), publicKey, modulus, hashAlgorithm);

                    // 显示结果
                    resultTextArea.setText(
                            "解密成功！\n解密后的字符串: " + new String(decryptedData) +
                                    (isValid ? "\n签名验证通过，数据未被篡改！" : "\n签名验证失败，数据可能已被篡改！")
                    );
                } else if ("File".equals(inputType)) {
                    // 解密文件
                    // 创建 JFileChooser，并将默认路径设置为当前工作目录
                    File filesDir = new File(currentDir, "files");
                    JFileChooser fileChooser = new JFileChooser(filesDir);
                    fileChooser.setDialogTitle("选择加密文件");
                    int returnValue = fileChooser.showOpenDialog(null);
                    if (returnValue != JFileChooser.APPROVE_OPTION) {
                        JOptionPane.showMessageDialog(null, "未选择加密文件！");
                        return;
                    }
                    File encryptedFile = fileChooser.getSelectedFile();
                    System.out.println("选择的加密文件路径: " + encryptedFile.getAbsolutePath());

                    fileChooser.setDialogTitle("选择签名文件");
                    returnValue = fileChooser.showOpenDialog(null);
                    if (returnValue != JFileChooser.APPROVE_OPTION) {
                        JOptionPane.showMessageDialog(null, "未选择签名文件！");
                        return;
                    }
                    File signatureFile = fileChooser.getSelectedFile();
                    System.out.println("选择的签名文件路径: " + signatureFile.getAbsolutePath());

                    // 读取文件内容
                    byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
                    byte[] signatureBytes = Files.readAllBytes(signatureFile.toPath());

                    BigInteger signature = new BigInteger(signatureBytes);

                    // 解密文件
                    byte[] decryptedData = EncryptionUtils.decrypt(encryptionAlgorithm, encryptedData, symmetricKey);

                    // 验证签名
                    String hashAlgorithm = (String) hashAlgorithmDropdown.getSelectedItem();
                    boolean isValid = EncryptionUtils.verifySignature(signature, decryptedData, new RSA(), publicKey, modulus, hashAlgorithm);

                    // 创建 JFileChooser 实例，并将默认目录设置为 'files' 文件夹
                    // 创建默认的保存文件
                    File defaultFile = new File(filesDir, "decrypted_output");
                    // 创建 JFileChooser 实例，并将默认目录设置为 'files' 文件夹
                    JFileChooser saveChooser = new JFileChooser(filesDir);
                    // 设置对话框标题
                    saveChooser.setDialogTitle("选择解密文件保存路径");
                    // 设置默认的保存文件
                    saveChooser.setSelectedFile(defaultFile);


                    // 显示保存对话框
                    int saveReturnValue = saveChooser.showSaveDialog(null);
                    if (saveReturnValue == JFileChooser.APPROVE_OPTION) {
                        // 获取用户选择的文件
                        File saveFile = saveChooser.getSelectedFile();
                        // 检查文件是否已存在
                        if (saveFile.exists()) {
                            int response = JOptionPane.showConfirmDialog(null,
                                    "文件已存在，是否覆盖？", "确认",
                                    JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                            if (response != JOptionPane.YES_OPTION) {
                                return; // 用户选择不覆盖，退出方法
                            }
                        }
                        // 将解密后的数据写入文件
                        Files.write(saveFile.toPath(), decryptedData);
                        // 显示保存成功的消息
                        JOptionPane.showMessageDialog(null,
                                "解密成功！解密文件保存为: " + saveFile.getAbsolutePath() +
                                        (isValid ? "\n签名验证通过，数据未被篡改！" : "\n签名验证失败，数据可能已被篡改！")
                        );
                    } else {
                        System.out.println("用户取消了保存操作。");
                    }
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "解密失败: " + ex.getMessage());
            }
        });

    }

    private static String saveKeyToFile(byte[] key, String fileName) throws IOException {
        String keyFilePath = File.separator + fileName;
        try (FileOutputStream fos = new FileOutputStream(keyFilePath)) {
            fos.write(key);
        }
        return keyFilePath;
    }

    private static String saveBigIntegerToFile(BigInteger key, String fileName) throws IOException {
        String keyFilePath =File.separator + fileName;
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(keyFilePath))) {
            oos.writeObject(key);
        }
        return keyFilePath;
    }

    // 读取对称密钥
    private static byte[] readSymmetricKey(String fileName) {
        // 获取当前工作目录
        String currentDir = System.getProperty("user.dir");
        // 指定 files 文件夹路径
        String filesDirPath = currentDir + File.separator + "files";
        // 创建 JFileChooser，并将默认路径设置为当前工作目录
        JFileChooser fileChooser = new JFileChooser(new File(filesDirPath));
        fileChooser.setDialogTitle("选择对称密钥文件");
        int userSelection = fileChooser.showOpenDialog(null);
        if (userSelection != JFileChooser.APPROVE_OPTION) {
            JOptionPane.showMessageDialog(null, "未选择对称密钥文件！");
            return null;
        }
        File keyFile = fileChooser.getSelectedFile();
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            byte[] key = fis.readAllBytes();
            System.out.println("对称密钥已从文件读取：" + keyFile.getAbsolutePath());
            return key;
        } catch (IOException ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(null, "读取对称密钥失败：" + ex.getMessage(),
                    "读取失败", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    // 读取以 BigInteger 格式存储的公钥或私钥
    private static BigInteger readBigIntegerKey(String fileName) {
        // 获取当前工作目录
        String currentDir = System.getProperty("user.dir");
        // 指定 files 文件夹路径
        String filesDirPath = currentDir + File.separator + "files";
        // 创建 JFileChooser，并将默认路径设置为当前工作目录
        JFileChooser fileChooser = new JFileChooser(new File(filesDirPath));
        if (Objects.equals(fileName, "public.key")) fileChooser.setDialogTitle("选择公钥文件");
        if (Objects.equals(fileName, "modulus.key")) fileChooser.setDialogTitle("选择RSA模数文件");
        int userSelection = fileChooser.showOpenDialog(null);
        if (userSelection != JFileChooser.APPROVE_OPTION) {
            JOptionPane.showMessageDialog(null, "未选择" + fileName + "文件！");
            return null;
        }
        File keyFile = fileChooser.getSelectedFile();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(keyFile))) {
            BigInteger key = (BigInteger) ois.readObject();
            System.out.println(fileName + "已从文件读取：" + keyFile.getAbsolutePath());
            return key;
        } catch (IOException | ClassNotFoundException ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(null, "读取" + fileName + "失败：" + ex.getMessage(),
                    "读取失败", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    private static JTextField addPathField(JPanel panel, GridBagConstraints gbc, String labelText, String defaultPath) {
        JLabel label = new JLabel(labelText);
        JTextField textField = new JTextField(defaultPath);
        textField.setColumns(30); // 设置文本框的列数以调整长度
        JButton browseButton = new JButton("浏览");
        browseButton.setPreferredSize(new Dimension(60, 25)); // 设置按钮的首选大小

        // 布局设置
        gbc.gridx = 0;
        gbc.gridy = GridBagConstraints.RELATIVE;
        panel.add(label, gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(textField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        panel.add(browseButton, gbc);

        // 浏览按钮事件处理
        browseButton.addActionListener(e -> {
            // 获取当前工作目录
            String currentDir = System.getProperty("user.dir");
            // 指定 files 文件夹路径
            String filesDirPath = currentDir + File.separator + "files";
            // 创建 JFileChooser，并将默认路径设置为当前工作目录
            JFileChooser fileChooser = new JFileChooser(new File(filesDirPath));
            fileChooser.setDialogTitle("选择文件保存路径");
            fileChooser.setSelectedFile(new File(textField.getText()));
            int userSelection = fileChooser.showSaveDialog(null);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();
                textField.setText(fileToSave.getAbsolutePath());
            }
        });

        return textField;
    }
}
