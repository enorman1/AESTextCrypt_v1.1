/**
 * Copyright 2013 Chris Wood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ceperman.textcrypt;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.FlowLayout;
import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.ceperman.textcrypt.CryptUtils.CipherInfo;

/**
 * Encrypts text using AES-256 and bcrypt. 
 * The key setup phase of bcrypt (number of rounds) is variable and adjusted
 * automatically to take ~0.9 sec on the encrypting computer.
 * @author Chris Wood
 */
@SuppressWarnings({ "javadoc", "serial" })
public class TextCrypt extends JFrame implements ActionListener {
   private static Logger logger = Logger.getLogger(TextCrypt.class.getName());
   private boolean D = false; // debugging

   private JPasswordField fieldPassword;
   private JCheckBox pswdCheckbox = new JCheckBox();
   private JTextArea fieldText;
   private JButton btnEncrypt;
   private JButton btnDecrypt;
   private JButton btnUndo;
   private JCheckBox keyCheckbox = new JCheckBox();
   private JButton btnCopy;
   private JButton btnPaste;
   private JButton btnClear;

   private int maxKeyLength;
   private int keyLength;
   private String savedText;
   private boolean haveText;
   private boolean havePswd;

   /**
    * Launch the application
    */
   public static void main(String[] args) {
      EventQueue.invokeLater(new Runnable() {
         public void run() {
            try {
               TextCrypt frame = new TextCrypt();
               frame.pack();
               frame.setMinimumSize(frame.getPreferredSize());

               // centre the window
               Dimension maxWindow = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds()
                           .getSize();
               frame.setSize(500, 600);
               frame.setLocation(maxWindow.width / 2 - frame.getWidth() / 2, maxWindow.height / 2 - frame.getHeight()
                           / 2);

               frame.setVisible(true);
            } catch (Exception e) {
               e.printStackTrace();
            }
         }
      });
   }

   /**
    * Initialize TextCrypt
    *  Check/enable BouncyCastle crypto provider. 
    *  Create the UI.
    */
   public TextCrypt() {
      try {
         CryptUtils.checkBCProvider();
      } catch (NoClassDefFoundError e) {
         JOptionPane.showMessageDialog(this, Messages.getString("no_bcprov"), Messages.getString("no_bcprov_title"),
                     JOptionPane.ERROR_MESSAGE);
         System.exit(16);
      }
      
      try {
         maxKeyLength = Math.min(CryptUtils.getMaximumKeyLength(), 256);
      } catch (NoSuchAlgorithmException e1) {
         maxKeyLength = 128;
      }
      keyLength = maxKeyLength;
      setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
      setTitle(Messages.getString("main_title"));
      JPanel cp = new JPanel();
      setContentPane(cp);
      cp.setLayout(new BoxLayout(cp, BoxLayout.PAGE_AXIS));
      cp.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

      // password stuff
      addPasswordFields(cp);
      // encrypt/decrypt buttons
      addCryptActions(cp);
      // textarea
      addTextArea(cp);
      // copy/paste buttons
      addClipboardActions(cp);
   }

   @Override
   public void actionPerformed(ActionEvent event) {
      if (D) logger.log(Level.INFO, "command is " + event.getActionCommand());
      if (event.getActionCommand().equals("encrypt")) {
         // save text
         savedText = fieldText.getText();
         btnUndo.setEnabled(true);
         // show reduced key length if being used
         if (keyLength < 256) {
            keyCheckbox.setSelected(true);
         }
         encrypt();
      } else if (event.getActionCommand().equals("decrypt")) {
         // save text
         savedText = fieldText.getText();
         btnUndo.setEnabled(true);
         decrypt();
      } else if (event.getActionCommand().equals("undo")) {
         if (savedText != null) {
            fieldText.setText(savedText);
         }
      } else if (event.getActionCommand().equals("copy")) {
         StringSelection stringSelection = new StringSelection(fieldText.getText());
         Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
      } else if (event.getActionCommand().equals("paste")) {
         Transferable transferable = Toolkit.getDefaultToolkit().getSystemClipboard().getContents(null);
         try {
            if (transferable != null && transferable.isDataFlavorSupported(DataFlavor.stringFlavor)
                        && transferable.getTransferData(DataFlavor.stringFlavor) != null
                        && ((String) transferable.getTransferData(DataFlavor.stringFlavor)).length() > 0) {
               fieldText.setText((String) transferable.getTransferData(DataFlavor.stringFlavor));
            } else {
               JOptionPane.showMessageDialog(this, Messages.getString("no_data_on_clipboard"),
                           Messages.getString("empty_clipboard_title"), JOptionPane.ERROR_MESSAGE);
            }
         } catch (Exception e) {
            JOptionPane.showMessageDialog(this, Messages.getString("no_data_on_clipboard"),
                        Messages.getString("clipboard_error_title"), JOptionPane.ERROR_MESSAGE);
         }
      } else if (event.getActionCommand().equals("clear")) {
         fieldText.setText("");
         haveText = false;
         enabledOrDisableBtns();
      }
   }

   private void enabledOrDisableBtns() {
      if (haveText && havePswd) {
         btnEncrypt.setEnabled(true);
         btnDecrypt.setEnabled(true);
      } else {
         btnEncrypt.setEnabled(false);
         btnDecrypt.setEnabled(false);
      }
   }

   /*
    * Encrypt the text.
    * Preceding the encrypted text is a header:
    *    salt length
    *    salt
    *    bcrypt rounds
    *    keylength-1
    * which is used for the decryption.
    */
   private void encrypt() {
      try {
         char[] pswdChars = fieldPassword.getPassword();
         byte[] pswdBytes = Charset.forName("UTF-8").encode(CharBuffer.wrap(pswdChars)).array();
         CipherInfo cipherInfo = CryptUtils
                     .createCiphers(pswdBytes, null, 0, keyLength);
         ExpandableByteBuffer bbuf = new ExpandableByteBuffer(32);
         bbuf.put((byte) cipherInfo.salt.length);
         bbuf.put(cipherInfo.salt);
         bbuf.put((byte) cipherInfo.rounds);
         // store the keylength-1 so max keylength (256) will fit in 1 byte
         bbuf.put((byte) (keyLength - 1));
         byte[] encryptedBytes = cipherInfo.encryptCipher.doFinal(fieldText.getText().getBytes("UTF-8"));
         bbuf.put(encryptedBytes);
         String encodedData = Base64.encodeBytes(bbuf.getBytes());
         fieldText.setText(encodedData);
      } catch (Exception e) {
         fieldText.setText(Messages.getString("encryption_failed"));
      }
   }

   /*
    * Decrypt the text, using the info from the header and the password
    * supplied by the user. 
    */
   private void decrypt() {
      try {
         byte[] decodedBytes = Base64.decode(fieldText.getText().getBytes("UTF-8"));
         byte[] salt = new byte[decodedBytes[0]];
         System.arraycopy(decodedBytes, 1, salt, 0, salt.length);
         int rounds = decodedBytes[salt.length + 1] & 0xFF;
         keyLength = decodedBytes[salt.length + 2] & 0xFF;
         // correct the keylength
         keyLength++;
         if (keyLength < 256) {
            keyCheckbox.setSelected(true);
         } else {
            keyCheckbox.setSelected(false);
         }
         byte[] encryptedBytes = new byte[decodedBytes.length - (salt.length + 3)];
         System.arraycopy(decodedBytes, salt.length + 3, encryptedBytes, 0, encryptedBytes.length);
         char[] pswdChars = fieldPassword.getPassword();
         byte[] pswdBytes = Charset.forName("UTF-8").encode(CharBuffer.wrap(pswdChars)).array();
         CipherInfo cipherInfo = CryptUtils.createCiphers(pswdBytes, salt, rounds,
                     keyLength);
         byte[] decryptedBytes = cipherInfo.decryptCipher.doFinal(encryptedBytes);
         fieldText.setText(new String(decryptedBytes, "UTF-8"));
      } catch (Exception e) {
         fieldText.setText(Messages.getString("decryption_failed"));
      }
   }

   /*
    * Add password fields to UI
    * @param cp
    */
   private void addPasswordFields(JPanel cp) {
      JPanel pswdHdrPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
      pswdHdrPane.add(new JLabel(Messages.getString("enter_password"), JLabel.LEFT));
      cp.add(pswdHdrPane);
      JPanel pswdPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
      fieldPassword = new JPasswordField();
      fieldPassword.getDocument().addDocumentListener(new DocumentListener() {
         @Override
         public void changedUpdate(DocumentEvent arg0) {
         }

         @Override
         public void insertUpdate(DocumentEvent arg0) {
            havePswd = true;
            enabledOrDisableBtns();
         }

         @Override
         public void removeUpdate(DocumentEvent arg0) {
            if (fieldPassword.getPassword().length == 0) {
               havePswd = false;
            }
            enabledOrDisableBtns();
         }
      });
      fieldPassword.setColumns(23);
      pswdPane.add(fieldPassword);
      pswdPane.add(pswdCheckbox);
      pswdCheckbox.setBorder(BorderFactory.createEmptyBorder(10, 30, 10, 0));
      pswdCheckbox.addActionListener(new ActionListener() {
         @Override
         public void actionPerformed(ActionEvent arg0) {
            if (pswdCheckbox.isSelected()) {
               fieldPassword.setEchoChar((char) 0);
            } else {
               fieldPassword.setEchoChar('*');
            }
         }
      });
      pswdPane.add(new JLabel(Messages.getString("show_password")));
      cp.add(pswdPane);
   }

   /*
    * Add encrypt/decrypt actions and key control to UI
    * @param cp
    */
   private void addCryptActions(JPanel cp) {
      JPanel cryptButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
      btnEncrypt = new JButton(Messages.getString("encrypt"));
      btnEncrypt.setActionCommand("encrypt");
      btnEncrypt.setEnabled(false); // initially disabled
      btnEncrypt.addActionListener(this);
      cryptButtons.add(btnEncrypt);
      btnDecrypt = new JButton(Messages.getString("decrypt"));
      btnDecrypt.setActionCommand("decrypt");
      btnDecrypt.setEnabled(false); // initially disabled
      btnDecrypt.addActionListener(this);
      cryptButtons.add(btnDecrypt);
      btnUndo = new JButton(Messages.getString("undo"));
      btnUndo.setActionCommand("undo");
      btnUndo.setEnabled(false); // initially disabled
      btnUndo.addActionListener(this);
      cryptButtons.add(btnUndo);
      cryptButtons.add(keyCheckbox);
      keyCheckbox.setBorder(BorderFactory.createEmptyBorder(10, 30, 10, 0));
      keyCheckbox.addActionListener(new ActionListener() {
         @Override
         public void actionPerformed(ActionEvent arg0) {
            if (keyCheckbox.isSelected()) {
               keyLength = 128;
            } else {
               keyLength = maxKeyLength;
            }
         }
      });
      cryptButtons.add(new JLabel(Messages.getString("reduced_keylength")));
      cp.add(cryptButtons);
   }

   /*
    * Ad textarea to UI
    * @param cp
    */
   private void addTextArea(JPanel cp) {
      JPanel textPane = new JPanel(new BorderLayout());
      textPane.setBorder(BorderFactory.createLineBorder(getBackground(), 5));
      fieldText = new JTextArea();
      fieldText.setLineWrap(true);
      fieldText.setWrapStyleWord(true);
      fieldText.getDocument().addDocumentListener(new DocumentListener() {
         @Override
         // not fired by plain documents
         public void changedUpdate(DocumentEvent e) {
         }

         @Override
         public void insertUpdate(DocumentEvent e) {
            haveText = true;
            enabledOrDisableBtns();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            if (fieldText.getText().isEmpty()) {
               haveText = false;
               enabledOrDisableBtns();
            }
         }
      });
      JScrollPane jScrollPane = new JScrollPane(fieldText);
      jScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
      textPane.add(jScrollPane, BorderLayout.CENTER);
      cp.add(textPane);
   }

   /*
    * Add clipboard action buttons to UI
    * @param cp
    */
   private void addClipboardActions(JPanel cp) {
      JPanel clipboardButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
      btnCopy = new JButton(Messages.getString("copy_to_clipboard"));
      btnCopy.setActionCommand("copy");
      btnCopy.addActionListener(this);
      clipboardButtons.add(btnCopy);
      btnPaste = new JButton(Messages.getString("paste_from_clipboard"));
      btnPaste.setActionCommand("paste");
      btnPaste.addActionListener(this);
      clipboardButtons.add(btnPaste);
      btnClear = new JButton(Messages.getString("clear_text"));
      btnClear.setActionCommand("clear");
      btnClear.addActionListener(this);
      clipboardButtons.add(btnClear);
      cp.add(clipboardButtons);
   }

}
