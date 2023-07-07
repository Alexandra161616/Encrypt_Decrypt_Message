using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace mergiterog
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        string parola;
        string encriptat;

        //Constanta asta determina keysize ul algoritmului de criptare in biti
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 256;

        //Constanta asta determina numarul de iteratii al functiei ce genereaza password ul
        private const int DerivationIterations = 1000;

        public static string Encrypt(string plainText, string passPhrase)
        {
           // Salt ul si IV sunt generate random de fiecare data  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // A creat bitii finali ca o concatenare de random salt bites, random IV bites si cipher bites Create the final bytes 
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
             // Ia stream ul complet de bytes care reprezinta: 
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Ia bytes de salt luand primii 32 bytes din cipherText bytes pusi la dispozitie
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
           // Ia bytes IV luand primii 32 bytes din cipherText bytes pusi la dispozitie
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Ia cipher text bytes stergand primii 64 biti din string ul cipherText
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            using (var streamReader = new StreamReader(cryptoStream, Encoding.UTF8))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes ne vor da 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
               // Umple array ul cu cryptographically secure bytes random
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }


        private void button1_Click(object sender, EventArgs e)
        {
            if (textBox1.Text == "")
            {
                MessageBox.Show("Inca nu ai inserat text!!!");
            }
            else
            {
                Clipboard.SetText(textBox1.Text);
                textBox2.Text = Clipboard.GetText();
                string plaintext = textBox2.Text;

                string password = textBox3.Text;
                if (password == "")
                    MessageBox.Show("scrie parola");
                else
                {
                    parola = password;
                    textBox3.Clear();
                    string encryptedstring = Encrypt(plaintext, password);
                    textBox2.Text = encryptedstring;
                    encriptat = textBox2.Text;
                    textBox1.Clear();
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            string password2 = textBox3.Text;
            if (password2 != parola)
            {
                MessageBox.Show("Parola gresita, incearca din nou");
                textBox3.Clear();
            }
            else
            {
                string decryptedstring = Decrypt(encriptat, password2);
                textBox2.Text = decryptedstring;
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
    }
