import 'dart:convert';

import 'package:fpdart/fpdart.dart';
import 'package:http/http.dart' as http;

class AuthRemoteRepositories {
  Future<Either<String, Map<String, dynamic>>> signup(
      {required String name,
      required String email,
      required String password}) async {
    try {
      final response = await http.post(
          Uri.parse(
            'http://10.0.2.2:8000/auth/signup',
          ),
          headers: {
            'Content-Type': 'application/json; charset=UTF-8',
          },
          body: jsonEncode(
            {
              'name': name,
              'email': email,
              'password': password,
            },
          ));
      if (response.statusCode != 200) {
        return Left(response.body);
      }
      final user = jsonDecode(response.body) as Map<String, dynamic>;
      return Right(user); 
    } catch (e) {
      return Left(e.toString());
    }
  }

  Future<void> login({required String email, required String password}) async {
    try {
      final response = await http.post(
          Uri.parse(
            'http://10.0.2.2:8000/auth/login',
          ),
          headers: {
            'Content-Type': 'application/json; charset=UTF-8',
          },
          body: jsonEncode(
            {
              'email': email,
              'password': password,
            },
          ));
      print(response.body);
      print(response.statusCode);
    } catch (e) {
      print(e);
    }
  }
}
