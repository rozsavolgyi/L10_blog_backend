<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends BaseController
{
    public function register(Request $request){
        $validator= Validator::make(
            $request->all(),
            [
                'name'=>'required',
                'email'=>'required|email|unique:App\Models\user,email',
                'password'=>'required',
                'confirm_password'=>'required|same:password',
                'role'=> 'required|integer'
            ],
            [
                'name.required'=>"Kötelező kitölteni!",
                'email.required'=>"Kötelező kitölteni!",
                'email.email'=>"Hibás email cím!",
                'email.unique'=>"Az email cím már létezik",
                'password.required'=>"Kötelező kitölteni!",
                'confirm_password.required'=>"Kötelező kitölteni!",
                'confirm_password.same'=>"A jelszó nem egyezzik!",
                'role.required'=>"Kötelező kitölteni!",
                'role.integer'=> "Csak szám lehet!"
            ]
        );
        if ($validator->fails()) {
            return $this->sendError('Hibás adatok!',$validator->errors(),400);
        }

        $input=$request->all();
        $input['password']=bcrypt($input['password']);
        $user= User::create($input);
        $response=[
            "name"=>$user->name,
            "token"=>$user->createToken('Secret')->plainTextToken
        ];

        return $this->sendResponse($response,'Sikeres regisztáció!',201);
    }

    public function login(Request $request){
        if (Auth::attempt(['email'=> $request->email,
        'password'=>$request->password])) {
            $user=Auth::user();
            $response=[
                'name'=>$user->name,
                'token'=>$user->createToken('Secret')->plainTextToken,
                'id'=>$user->id,
                'role'=>$user->role
            ];
            //dd('ok');
            return $this->sendResponse($response,'Sikeres bejelentkezés!');
        }else {
            return $this->sendError('',['error'=>'Sikertelen bejelnetkezés!'],401);
        }
    }
    public function logout(){
        auth()->user()->tokens()->delete();
        return $this->sendResponse('','Sikeres kijelentkezés!');
    }
}
