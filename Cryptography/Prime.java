package Cryptography;
import java.math.BigInteger;
import java.util.Scanner;

public class Prime {
    public static void main(String args[]) {
        Scanner scanner = new Scanner(System.in);
        
        // System.out.print("Enter a number to check if it's prime: ");
        int number;
        try {
            System.out.print("Enter a number: ");
            number = Integer.parseInt(scanner.nextLine());
            
            // if (isPrime(number)) {
            //     System.out.println(number + " is a prime number");
            // } else {
            //     System.out.println(number + " is not a prime number");
            // }
            
            // System.out.print("Do you want to check if two numbers are co-prime? (yes/no): ");
            // String response = scanner.nextLine();
            
            // if (response.equalsIgnoreCase("yes")) {
            if (true) {
                System.out.print("Enter a second number: ");
                try {
                    int secondNumber = Integer.parseInt(scanner.nextLine());
                    
                    BigInteger a = BigInteger.valueOf(number);
                    BigInteger b = BigInteger.valueOf(secondNumber);
                    
                    if (isCoPrime(a, b)) {
                        System.out.println(number + " and " + secondNumber + " are co-prime");
                    } else {
                        System.out.println(number + " and " + secondNumber + " are not co-prime");
                    }

                    System.out.println("Totient of " + secondNumber + " is: " + totient(b));

                    System.out.println("GCD of " + number + " and " + secondNumber + " is: " + euclidianGCD(number, secondNumber));


                } catch (NumberFormatException e) {
                    System.out.println("Please provide a valid integer for the second number");
                }
            }
        } catch (NumberFormatException e) {
            System.out.println("Please provide a valid integer");
        } finally {
            scanner.close();
        }
    }
    
    public static boolean isPrime(int n) {
        if (n <= 1) {
            return false;
        }
        if (n <= 3) {
            return true;
        }
        if (n % 2 == 0 || n % 3 == 0) {
            return false;
        }
        
        for (int i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isCoPrime(BigInteger a, BigInteger b){
        return a.gcd(b).equals(BigInteger.ONE);
    }

    public static int totient(BigInteger n){
        int result = 1;
        for (int i = 2; i < n.intValue(); i++) {
            if (isCoPrime(BigInteger.valueOf(i), n)) {
                result++;
            }
        }
        return result;
    }
    
    public static int euclidianGCD(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }
}