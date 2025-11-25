using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Timers;

namespace PracticalPartCoursework
{
    // Клас для зберігання даних користувача
    public class User
    {
        public string Username { get; set; }  // Ім'я користувача
        public string Password { get; set; }  // Пароль користувача
        public Dictionary<string, string> CatalogAccess { get; set; }  // Права доступу до каталогів A,B,C,D,E
        public DateTime RegistrationTime { get; set; }  // Час реєстрації
        public DateTime LastActivity { get; set; }  // Час останньої активності
        public DateTime PasswordExpiry { get; set; }  // Термін дії пароля

        // Конструктор для ініціалізації словника
        public User()
        {
            CatalogAccess = new Dictionary<string, string>(); // Створюємо порожній словник для прав доступу
        }
    }

    // Клас для контролю доступу до каталогів
    public class AccessControlSystem
    {
        // Визначаємо 3 рівні доступу (S=3) для каталогів A,B,C,D,E
        // Кожен каталог має мінімальні необхідні права для доступу
        private Dictionary<string, string> catalogRequirements = new Dictionary<string, string>
        {
            {"A", "RWE"},  // Максимальні права - читання, запис, виконання
            {"B", "REA"},   // Середні права - читання, виконання, додавання
            {"C", "R"},     // Мінімальні права - тільки читання
            {"D", "E"},    // Мінімальні права - тільки виконання
            {"E", "RE"}     // Середні права - читання, виконання
        };

        // Метод перевірки доступу користувача до каталогу
        public bool CheckAccess(User user, string catalog)
        {
            // Перевіряємо, чи існує такий каталог
            if (!catalogRequirements.ContainsKey(catalog))
            {
                Console.WriteLine($"Каталог {catalog} не існує");
                return false;
            }

            // Перевіряємо, чи є у користувача права до цього каталогу
            if (user.CatalogAccess == null || !user.CatalogAccess.ContainsKey(catalog))
            {
                Console.WriteLine($"Користувач {user.Username} не має прав до каталогу {catalog}");
                return false;
            }

            string userRights = user.CatalogAccess[catalog];   // Права користувача
            string requiredRights = catalogRequirements[catalog];    // Необхідні права

            // Перевіряємо, чи є у користувача необхідні права
            // Порівнюємо кожен необхідний символ з правами користувача
            foreach (char right in requiredRights)
            {
                if (!userRights.Contains(right))
                {
                    Console.WriteLine($"Недостатньо прав! Потрібно: {requiredRights}, Ваші: {userRights}");
                    return false;
                }
            }

            Console.WriteLine($"Доступ до каталогу {catalog} дозволено");
            return true;
        }

        // Показуємо тільки доступні каталоги (приховуємо недоступні)
        public void ShowAvailableCatalogs(User user)
        {
            Console.WriteLine("\n=== ДОСТУПНІ КАТАЛОГИ ===");
            foreach (var catalog in catalogRequirements)
            {
                // Перевіряємо доступ до кожного каталогу і показуємо тільки доступні
                if (user.CatalogAccess != null && user.CatalogAccess.ContainsKey(catalog.Key) &&
                    CheckAccess(user, catalog.Key))
                {
                    Console.WriteLine($" Каталог {catalog.Key} - права: {user.CatalogAccess[catalog.Key]}");
                }
                // Недоступні каталоги не показуємо (приховуємо)
            }
        }
    }

    // Клас для періодичної автентифікації (рукостискання)
    public class Handshake
    {
        private readonly string _questionsPath;  // Шлях до файлу з питаннями
        private readonly TimeSpan _period;       // Період перевірки (T=10 секунд)
        private DateTime _lastValidationPassedAt;// Час останньої успішної перевірки
        private readonly List<(double X, double Y)> _questions = new();// Список питань X-Y
        private const double A_VALUE = 4.0;      // Коефіцієнт a=4 для функції F(X)=lg(a*x)

        public Handshake(string questionsPath = "ask.txt", int periodSeconds = 10)
        {
            _questionsPath = questionsPath;
            _period = TimeSpan.FromSeconds(periodSeconds);// T=10 секунд
            _lastValidationPassedAt = DateTime.Now;

            _EnsureQuestionsFile();// Створюємо файл питань, якщо не існує
            _LoadQuestions();// Завантажуємо питання з файлу

        }

        // Створюємо файл з питаннями, якщо він не існує
        private void _EnsureQuestionsFile()
        {
            if (!File.Exists(_questionsPath))
            {
                // Стандартні питання для математичної автентифікації
                var defaultQuestions = new List<(double X, double Y)>
                {
                    (2, 0.9),   // lg(4*2) = lg(8) ≈ 0.9
                    (5, 1.3),   // lg(4*5) = lg(20) ≈ 1.3
                    (10, 1.6),  // lg(4*10) = lg(40) ≈ 1.6
                    (8, 1.5),   // lg(4*8) = lg(32) ≈ 1.5
                    (15, 1.8)   // lg(4*15) = lg(60) ≈ 1.8
                };

                // Записуємо питання у файл
                using (var writer = new StreamWriter(_questionsPath, false, Encoding.UTF8))
                {
                    writer.WriteLine("# x|y — значення для перевірки автентичності (Y = lg(4*x))");
                    foreach (var (x, y) in defaultQuestions)
                        writer.WriteLine($"{x}|{y:F1}"); // Формат: X|Y з одним знаком після коми
                }
            }
        }

        // Перевіряємо, чи потрібна автентифікація (кожні T секунд)
        public bool ShouldAuthenticate()
        {
            return DateTime.Now - _lastValidationPassedAt >= _period;
        }

        // Завантажуємо питання з файлу
        private void _LoadQuestions()
        {
            try
            {
                if (!File.Exists(_questionsPath))
                    throw new FileNotFoundException("Файл ask.txt не знайдено.");

                var lines = File.ReadAllLines(_questionsPath, Encoding.UTF8);

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#")) // Пропускаємо коментарі
                        continue;

                    try
                    {
                        var parts = trimmed.Split('|'); // Розділяємо на X і Y
                        if (parts.Length != 2)
                            continue;

                        // Парсимо числа та додаємо до списку питань
                        if (double.TryParse(parts[0], out double x) &&
                            double.TryParse(parts[1], out double y))
                        {
                            _questions.Add((x, y));
                        }
                    }
                    catch
                    {
                        continue; // Пропускаємо помилкові рядки
                    }
                }

                if (_questions.Count == 0)
                    throw new InvalidOperationException("Файл ask.txt порожній або має неправильний формат.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка завантаження запитань: {ex.Message}");
            }
        }

        // Виконуємо автентифікацію користувача
        public bool PerformAuthentication(User user)
        {
            if (_questions.Count == 0)
            {
                Console.WriteLine("Запитання відсутні.");
                return false;
            }

            // Вибираємо випадкове питання
            var rnd = new Random();
            var (x, y) = _questions[rnd.Next(_questions.Count)];

            Console.WriteLine($"\nПеревірка автентичності для користувача [{user.Username}]");
            Console.WriteLine($"Введіть значення Y = lg(4 * {x})"); // F(X) = lg(4*x)
            Console.Write("Ваша відповідь: ");

            string input = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(input))
                return false;

            // Конвертуємо введену відповідь в число (замінюємо крапку на кому)
            if (!double.TryParse(input.Replace('.', ','), out double yUser))
            {
                Console.WriteLine("Невірний формат числа.");
                return false;
            }

            // Порівнюємо відповідь з правильною (з невеликою похибкою)
            bool isPassed = Math.Abs(Math.Round(yUser, 1) - Math.Round(y, 1)) < 0.01;

            if (isPassed)
            {
                _lastValidationPassedAt = DateTime.Now; // Оновлюємо час останньої перевірки
                Console.WriteLine("Автентифікацію пройдено.");
                return true;
            }

            Console.WriteLine($"Автентифікацію не пройдено. Очікувалось: {y:F1}");
            return false;
        }
    }

    // Основний клас системи
    public class SecuritySystem
    {
        private List<User> users; // Список всіх користувачів
        private const int MAX_USERS = 8; // N = 8 (максимальна кількість користувачів)
        private const int PASSWORD_VALIDITY_DAYS = 30; // Безпечний час використання пароля
        private const double A_CONSTANT = 4; // a = 4 (коефіцієнт для математичної функції)
        private string adminPassword = "admin123"; // Пароль адміністратора
        private AccessControlSystem accessControl; // Система контролю доступу
        private User currentUser; // Система контролю доступу

        public SecuritySystem()
        {
            // Встановлюємо кодування для української мови
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            users = new List<User>();
            accessControl = new AccessControlSystem();
            LoadUsers(); // Завантажуємо користувачів з файлу
        }

        public User GetCurrentUser() => currentUser; // Отримуємо поточного користувача

        // Виходимо з системи
        public void LogoutUser()
        {
            if (currentUser != null)
            {
                LogActivity($"Вихід з системи: {currentUser.Username}");
                currentUser = null; // Скидаємо поточного користувача
            }
        }

        // Метод для перевірки пароля адміністратора
        public bool CheckAdminPassword(string password)
        {
            return password == adminPassword; 
        }

        // 1. Реєстрація користувача (тільки адміністратор)
        public bool RegisterUser(string username, string password, Dictionary<string, string> catalogAccess)
        {
            // Перевіряємо, чи не перевищено максимальну кількість користувачів
            if (users.Count >= MAX_USERS)
            {
                Console.WriteLine($"Досягнуто максимум користувачів: {MAX_USERS}");
                return false;
            }

            // Перевіряємо, чи не існує вже користувач з таким іменем
            if (users.Any(u => u.Username == username))
            {
                Console.WriteLine("Користувач вже існує!");
                return false;
            }

            // Створюємо нового користувача
            var newUser = new User
            {
                Username = username,
                Password = password,
                RegistrationTime = DateTime.Now,
                LastActivity = DateTime.Now,
                PasswordExpiry = DateTime.Now.AddDays(PASSWORD_VALIDITY_DAYS) // Пароль дійсний 30 днів
            };

            // Копіюємо всі права доступу з переданого словника
            if (catalogAccess != null)
            {
                foreach (var access in catalogAccess)
                {
                    newUser.CatalogAccess[access.Key] = access.Value;
                }
            }

            try
            {
                users.Add(newUser);
                SaveUsers(); // Зберігаємо зміни у файл
                LogActivity($"Зареєстровано: {username}");
                Console.WriteLine($"Користувач {username} успішно зареєстрований");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка збереження: {ex.Message}");
                LogActivity($"Помилка реєстрації: {username} - {ex.Message}");
                return false;
            }
        }

        // Видалення користувача
        public bool DeleteUser(string username)
        {
            var user = users.FirstOrDefault(u => u.Username == username);
            if (user == null)
            {
                Console.WriteLine("Користувач не знайдений!");
                return false;
            }

            users.Remove(user);
            SaveUsers(); // Зберігаємо зміни
            LogActivity($"Видалено: {username}");
            Console.WriteLine($"Користувач {username} видалений");
            return true;
        }

        // 2. Ідентифікація користувача (вхід в систему)
        public bool IdentifyUser(string username, string password)
        {
            // Шукаємо користувача з відповідним іменем і паролем
            var user = users.FirstOrDefault(u => u.Username == username && u.Password == password);

            if (user != null)
            {
                // Перевіряємо, чи не вийшов термін дії пароля
                if (user.PasswordExpiry < DateTime.Now)
                {
                    Console.WriteLine("Термін дії пароля вийшов! Змініть пароль.");
                    LogActivity($"Спроба входу з простроченим паролем: {username}");
                    return false;
                }

                user.LastActivity = DateTime.Now; // Оновлюємо час активності
                currentUser = user; // Встановлюємо поточного користувача
                SaveUsers(); // Зберігаємо зміни
                LogActivity($"Успішний вхід: {username}");
                return true;
            }

            LogActivity($"Невдала спроба входу: {username}");
            return false;
        }

        // 3. Автентифікація (рукостискання) - математична перевірка
        public bool AuthenticateUser(double x)
        {
            if (currentUser == null)
            {
                Console.WriteLine("Користувач не авторизований!");
                return false;
            }

            double expectedY = Math.Round(Math.Log10(A_CONSTANT * x), 1); // F(X) = lg(a*x)
            Console.WriteLine($"Введіть відповідь для X = {x}: Y = lg(4 * {x})");
            Console.Write("Ваша відповідь (один знак після коми): ");

            if (double.TryParse(Console.ReadLine(), out double userAnswer))
            {
                double roundedUserAnswer = Math.Round(userAnswer, 1);

                // Порівнюємо з правильною відповіддю (допустима похибка 0.05)
                if (Math.Abs(roundedUserAnswer - expectedY) < 0.05)
                {
                    currentUser.LastActivity = DateTime.Now;
                    SaveUsers();
                    LogActivity($"Успішна автентифікація: {currentUser.Username}");
                    return true;
                }
            }

            Console.WriteLine($"Невірно! Очікувалось: {expectedY:F1}");
            LogActivity($"Невдала автентифікація: {currentUser.Username}");
            return false;
        }

        // Перевірка доступу до конкретного каталогу
        public void CheckCatalogAccess(string catalog)
        {
            if (currentUser == null)
            {
                Console.WriteLine("Спочатку увійдіть в систему!");
                return;
            }
            accessControl.CheckAccess(currentUser, catalog);
        }

        // Показуємо доступні каталоги
        public void ShowAvailableCatalogs()
        {
            if (currentUser == null)
            {
                Console.WriteLine("Спочатку увійдіть в систему!");
                return;
            }
            accessControl.ShowAvailableCatalogs(currentUser);
        }

        // Завантажуємо користувачів з файлу nameuser.txt
        private void LoadUsers()
        {
            try
            {
                users = new List<User>(); // Ініціалізація списку

                if (File.Exists("nameuser.txt"))
                {
                    var lines = File.ReadAllLines("nameuser.txt", Encoding.UTF8);
                    foreach (var line in lines)
                    {
                        // Новий формат: Користувач:user1; Пароль:1111; Реєстрація:06.11.2024; Дійсний до:06.12.2024; Каталоги: A=R; B=R; C=R; D=R; E=R
                        if (line.Contains("Користувач:"))
                        {
                            var user = new User();

                            // Розділяємо рядок на частини по "; "
                            var parts = line.Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries);

                            foreach (var part in parts)
                            {
                                // Шукаємо перше входження двокрапки для розділення ключа і значення
                                int colonIndex = part.IndexOf(':');
                                if (colonIndex > 0)
                                {
                                    string key = part.Substring(0, colonIndex).Trim();
                                    string value = part.Substring(colonIndex + 1).Trim();

                                    // Розпізнаємо тип даних та заповнюємо об'єкт користувача
                                    switch (key)
                                    {
                                        case "Користувач":
                                            user.Username = value;
                                            break;
                                        case "Пароль":
                                            user.Password = value;
                                            break;
                                        case "Реєстрація":
                                            user.RegistrationTime = DateTime.Parse(value);
                                            user.LastActivity = DateTime.Parse(value);
                                            break;
                                        case "Дійсний до":
                                            user.PasswordExpiry = DateTime.Parse(value);
                                            break;
                                        case "Каталоги":
                                            // Обробляємо каталоги у форматі A=R; B=R; C=R; D=R; E=R
                                            var catalogParts = value.Split(';');
                                            foreach (var catalogPart in catalogParts)
                                            {
                                                var catalogKeyValue = catalogPart.Trim().Split('=');
                                                if (catalogKeyValue.Length == 2)
                                                {
                                                    string catalogKey = catalogKeyValue[0].Trim();
                                                    string catalogValue = catalogKeyValue[1].Trim();
                                                    if ("ABCDE".Contains(catalogKey)) // Перевіряємо коректність каталогу
                                                    {
                                                        user.CatalogAccess[catalogKey] = catalogValue;
                                                    }
                                                }
                                            }
                                            break;
                                    }
                                }
                            }

                            if (!string.IsNullOrEmpty(user.Username))
                                users.Add(user);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка завантаження: {ex.Message}");
            }
        }

        // Зберігаємо користувачів у файл nameuser.txt
        private void SaveUsers()
        {
            try
            {
                var lines = new List<string>();
                foreach (var user in users)
                {
                    // Формуємо рядок з даними користувача
                    var lineParts = new List<string>
                    {
                        $"Користувач:{user.Username}",
                        $"Пароль:{user.Password}",
                        $"Реєстрація:{user.RegistrationTime:dd.MM.yyyy}",
                        $"Дійсний до:{user.PasswordExpiry:dd.MM.yyyy}"
                    };

                    // Завжди вказуємо всі каталоги A, B, C, D, E навіть якщо права = 0
                    var catalogParts = new List<string>();
                    string[] allCatalogs = { "A", "B", "C", "D", "E" };

                    foreach (string catalog in allCatalogs)
                    {
                        string rights = "0"; // за замовчуванням немає прав
                        if (user.CatalogAccess != null && user.CatalogAccess.ContainsKey(catalog))
                        {
                            rights = user.CatalogAccess[catalog];
                        }
                        catalogParts.Add($"{catalog}={rights}");
                    }

                    string catalogsString = string.Join("; ", catalogParts);
                    lineParts.Add($"Каталоги: {catalogsString}");
                    
                    // Об'єднуємо всі частини в один рядок
                    lines.Add(string.Join("; ", lineParts));
                }
                File.WriteAllLines("nameuser.txt", lines, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка збереження: {ex.Message}");
            }
        }

        // Логування дій у файл us_book.txt
        public void LogActivity(string activity)
        {
            try
            {
                string username = currentUser?.Username ?? "SYSTEM"; // Якщо немає користувача - SYSTEM
                string timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");

                // Новий формат журналу: кожна подія в окремому рядку
                string logEntry = $"Час: {timestamp}; Користувач: {username}; Подія: {activity};";

                File.AppendAllText("us_book.txt", logEntry + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка журналу: {ex.Message}");
            }
        }
    }

    // Система шифрування RSA
    public class RSACryptoSystem
    {
        private RSACryptoServiceProvider rsa;  // Об'єкт для роботи з RSA
        private const int KEY_SIZE = 512; // 512 біт для 64 десяткових знаків

        public RSACryptoSystem()
        {
            rsa = new RSACryptoServiceProvider(KEY_SIZE);  // Створюємо RSA провайдер
        }

        // Генерація пари ключів RSA
        public void GenerateKeys()
        {
            string publicKey = rsa.ToXmlString(false); // Відкритий ключ (без закритої частини)
            string privateKey = rsa.ToXmlString(true); // Закритий ключ (повна інформація)

            // Зберігаємо ключі у файли
            File.WriteAllText("public_key.txt", publicKey, Encoding.UTF8);
            File.WriteAllText("private_key.txt", privateKey, Encoding.UTF8);

            Console.WriteLine("Ключі RSA згенеровано (64 десяткових знаків)");
        }

        // Шифрування файлу за допомогою публічного ключа
        public void EncryptFile(string inputFile, string outputFile)
        {
            try
            {
                if (!File.Exists("public_key.txt"))
                {
                    Console.WriteLine("Спочатку згенеруйте ключі!");
                    return;
                }

                // Завантажуємо публічний ключ
                string publicKey = File.ReadAllText("public_key.txt", Encoding.UTF8);
                rsa.FromXmlString(publicKey);

                byte[] data = File.ReadAllBytes(inputFile);
                int keySize = rsa.KeySize / 8; // Розмір ключа в байтах
                int blockSize = keySize - 42; // Розмір блоку для шифрування (з урахуванням padding)
                int blocksCount = (int)Math.Ceiling((double)data.Length / blockSize);

                // Шифруємо файл по блокам
                using (var outputStream = new FileStream(outputFile, FileMode.Create))
                {
                    for (int i = 0; i < blocksCount; i++)
                    {
                        int length = Math.Min(blockSize, data.Length - i * blockSize);
                        byte[] block = new byte[length];
                        Array.Copy(data, i * blockSize, block, 0, length);

                        // Шифруємо блок даних
                        byte[] encryptedBlock = rsa.Encrypt(block, false);
                        outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
                    }
                }

                Console.WriteLine("Файл зашифровано");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка шифрування: {ex.Message}");
            }
        }

        // Розшифрування файлу за допомогою приватного ключа
        public void DecryptFile(string inputFile, string outputFile)
        {
            try
            {
                if (!File.Exists("private_key.txt"))
                {
                    Console.WriteLine("Приватний ключ не знайдено!");
                    return;
                }

                // Завантажуємо приватний ключ
                string privateKey = File.ReadAllText("private_key.txt", Encoding.UTF8);
                rsa.FromXmlString(privateKey);

                byte[] encryptedData = File.ReadAllBytes(inputFile);
                int keySize = rsa.KeySize / 8;
                int blocksCount = encryptedData.Length / keySize;
                
                // Розшифровуємо файл по блокам
                using (var outputStream = new MemoryStream())
                {
                    for (int i = 0; i < blocksCount; i++)
                    {
                        byte[] block = new byte[keySize];
                        Array.Copy(encryptedData, i * keySize, block, 0, keySize);
                        byte[] decryptedBlock = rsa.Decrypt(block, false); // Розшифровуємо блок
                        outputStream.Write(decryptedBlock, 0, decryptedBlock.Length);
                    }
                    File.WriteAllBytes(outputFile, outputStream.ToArray()); // Зберігаємо розшифрований файл
                }

                Console.WriteLine("Файл розшифровано");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка розшифрування: {ex.Message}");
            }
        }

        // ЦИФРОВИЙ ПІДПИС - створення підпису для файлу
        public void CreateDigitalSignature()
        {
            try
            {
                if (!File.Exists("private_key.txt"))
                {
                    Console.WriteLine("Приватний ключ не знайдено! Спочатку згенеруйте ключі.");
                    return;
                }

                if (!File.Exists("input.txt"))
                {
                    Console.WriteLine("Файл input.txt не знайдено!");
                    return;
                }

                // Завантажуємо приватний ключ
                string privateKey = File.ReadAllText("private_key.txt", Encoding.UTF8);
                rsa.FromXmlString(privateKey);

                // Читаємо дані з файлу
                byte[] data = File.ReadAllBytes("input.txt");

                // Створюємо цифровий підпис
                byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Виводимо підпис на дисплей
                Console.WriteLine("\n=== ЦИФРОВИЙ ПІДПИС ===");
                Console.WriteLine("Підпис у форматі Base64:");
                Console.WriteLine(Convert.ToBase64String(signature));

                Console.WriteLine("\nПідпис у hex-форматі:");
                Console.WriteLine(BitConverter.ToString(signature).Replace("-", ""));

                // Зберігаємо підпис у файл
                File.WriteAllText("signature.txt", Convert.ToBase64String(signature), Encoding.UTF8);
                Console.WriteLine("\nПідпис збережено у файл signature.txt");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка створення підпису: {ex.Message}");
            }
        }

        // Перевірка цифрового підпису
        public void VerifyDigitalSignature()
        {
            try
            {
                if (!File.Exists("public_key.txt"))
                {
                    Console.WriteLine("Публічний ключ не знайдено!");
                    return;
                }

                if (!File.Exists("input.txt"))
                {
                    Console.WriteLine("Файл input.txt не знайдено!");
                    return;
                }

                if (!File.Exists("signature.txt"))
                {
                    Console.WriteLine("Файл signature.txt не знайдено! Спочатку створіть підпис.");
                    return;
                }

                // Завантажуємо публічний ключ
                string publicKey = File.ReadAllText("public_key.txt", Encoding.UTF8);
                rsa.FromXmlString(publicKey);

                // Читаємо оригінальні дані та підпис
                byte[] data = File.ReadAllBytes("input.txt");
                string signatureBase64 = File.ReadAllText("signature.txt", Encoding.UTF8);
                byte[] signature = Convert.FromBase64String(signatureBase64);

                // Перевіряємо підпис публічним ключем
                bool isValid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                Console.WriteLine("\n=== ПЕРЕВІРКА ЦИФРОВОГО ПІДПИСУ ===");
                if (isValid)
                {
                    Console.WriteLine("Підпис ВАЛІДНИЙ - дані не змінювались");
                }
                else
                {
                    Console.WriteLine("Підпис НЕВАЛІДНИЙ - дані було змінено!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка перевірки підпису: {ex.Message}");
            }
        }
    }

    // Головний клас програми
    class Program
    {
        static void Main(string[] args)
        {
            // Встановлюємо кодування UTF-8 для підтримки української мови
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            // Створюємо об'єкти систем
            SecuritySystem securitySystem = new SecuritySystem();
            RSACryptoSystem cryptoSystem = new RSACryptoSystem();
            Handshake handshake = new Handshake();

            CreateTestFiles();

            // Головний цикл програми
            while (true)
            {
                var currentUser = securitySystem.GetCurrentUser();
                // Виводимо головне меню
                Console.WriteLine("\n=== СИСТЕМА БЕЗПЕКИ ===");
                Console.WriteLine("1. Реєстрація користувача (адмін)");
                Console.WriteLine("2. Видалення користувача (адмін)");
                Console.WriteLine("3. Вхід в систему");
                Console.WriteLine("4. Автентифікація (рукостискання)");
                Console.WriteLine("5. Перевірити доступ до каталогу");
                Console.WriteLine("6. Показати доступні каталоги");
                Console.WriteLine("=== ШИФРУВАННЯ RSA ===");
                Console.WriteLine("7. Генерація ключів RSA");
                Console.WriteLine("8. Шифрування файлу");
                Console.WriteLine("9. Розшифрування файлу");
                Console.WriteLine("=== ЦИФРОВИЙ ПІДПИС ===");
                Console.WriteLine("A. Створити цифровий підпис");
                Console.WriteLine("B. Перевірити цифровий підпис");
                Console.WriteLine("0. Вихід");
                Console.Write("Виберіть опцію: ");

                string choice = Console.ReadLine()?.ToUpper();

                // Перевіряємо, чи потрібна періодична автентифікація
                if (currentUser != null && handshake.ShouldAuthenticate())
                {
                    bool passed = handshake.PerformAuthentication(currentUser);
                    if (!passed)
                    {
                        Console.WriteLine("Автентифікацію не пройдено. Вас буде розлогінено.");
                        securitySystem.LogoutUser();
                        continue;
                    }
                }

                // Обробляємо вибір користувача
                switch (choice)
                {
                    case "1": RegisterUser(securitySystem); break;
                    case "2": DeleteUser(securitySystem); break;
                    case "3": LoginUser(securitySystem); break;
                    case "4": AuthenticateUser(securitySystem); break;
                    case "5": CheckCatalogAccess(securitySystem); break;
                    case "6": securitySystem.ShowAvailableCatalogs(); break;
                    case "7": cryptoSystem.GenerateKeys(); break;
                    case "8": cryptoSystem.EncryptFile("input.txt", "close.txt"); break;
                    case "9": cryptoSystem.DecryptFile("close.txt", "out.txt"); break;
                    case "A": cryptoSystem.CreateDigitalSignature(); break;
                    case "B": cryptoSystem.VerifyDigitalSignature(); break;
                    case "0":
                        securitySystem.LogActivity("Завершення роботи системи");
                        return;
                    default: Console.WriteLine("Невірний вибір!"); break;
                }
            }
        }

        // Створюємо тестові файли, якщо вони не існують
        static void CreateTestFiles()
        {
            if (!File.Exists("input.txt"))
            {
                string testText = @"Цей файл містить текст для перевірки роботи системи шифрування. Курсова робота з інформаційної безпеки.
                   Система використовує алгоритм RSA для захисту даних.Шифрування працює коректно!";

                File.WriteAllText("input.txt", testText, Encoding.UTF8);
                Console.WriteLine("Створено тестовий файл input.txt");
            }
        }

        // Метод реєстрації нового користувача (тільки для адміністратора)
        static void RegisterUser(SecuritySystem securitySystem)
        {
            Console.Write("Пароль адміністратора: ");
            string adminPass = Console.ReadLine();

            // МИТТЄВА перевірка пароля адміністратора
            if (!securitySystem.CheckAdminPassword(adminPass))
            {
                Console.WriteLine("Невірний пароль адміністратора!");
                return; // Виходимо з методу, не продовжуючи реєстрацію
            }

            Console.Write("Ім'я користувача: ");
            string username = Console.ReadLine();
            Console.Write("Пароль: ");
            string password = Console.ReadLine();

            var accessRights = new Dictionary<string, string>();  // Словник для прав доступу
            string[] catalogs = { "A", "B", "C", "D", "E" }; // Всі доступні каталоги

            Console.WriteLine("Вкажіть права доступу для кожного каталогу (R-читання, W-запис, E-виконання, A-додавання, M-зміна, 0-немає прав):");
            foreach (string catalog in catalogs)
            {
                Console.Write($"Каталог {catalog}: ");
                string rights = Console.ReadLine();
                // Якщо користувач нічого не ввів - ставимо "0" (немає прав)
                accessRights[catalog] = string.IsNullOrEmpty(rights) ? "0" : rights.ToUpper();
            }

            // Викликаємо метод без пароля адміністратора, оскільки вже перевірили
            securitySystem.RegisterUser(username, password, accessRights);
        }

        // Метод видалення користувача (тільки для адміністратора)
        static void DeleteUser(SecuritySystem securitySystem)
        {
            Console.Write("Пароль адміністратора: ");
            string adminPass = Console.ReadLine();

            // МИТТЄВА перевірка пароля адміністратора
            if (!securitySystem.CheckAdminPassword(adminPass))
            {
                Console.WriteLine("Невірний пароль адміністратора!");
                return; // Виходимо з методу, не продовжуючи видалення
            }

            Console.Write("Ім'я користувача для видалення: ");
            string username = Console.ReadLine();

            // Викликаємо метод без пароля адміністратора, оскільки вже перевірили
            securitySystem.DeleteUser(username);
        }

        // Метод входу користувача в систему
        static void LoginUser(SecuritySystem securitySystem)
        {
            Console.Write("Ім'я: ");
            string username = Console.ReadLine();
            Console.Write("Пароль: ");
            string password = Console.ReadLine();
            // Спроба ідентифікації користувача
            if (securitySystem.IdentifyUser(username, password))
                Console.WriteLine("Вхід успішний!");
            else
                Console.WriteLine("Невірні дані!");
        }

        // Метод математичної автентифікації (рукостискання)
        static void AuthenticateUser(SecuritySystem securitySystem)
        {
            if (securitySystem.GetCurrentUser() == null)
            {
                Console.WriteLine("Спочатку увійдіть!");
                return;
            }
            // Генеруємо випадкове число X для математичної задачі
            Random rand = new Random();
            securitySystem.AuthenticateUser(rand.Next(1, 100));
        }

        static void CheckCatalogAccess(SecuritySystem securitySystem)
        {
            if (securitySystem.GetCurrentUser() == null)
            {
                Console.WriteLine("Спочатку увійдіть!");
                return;
            }
            Console.Write("Каталог (A,B,C,D,E): ");
            securitySystem.CheckCatalogAccess(Console.ReadLine().ToUpper());
        }
    }
}
