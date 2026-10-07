<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;

class UserController extends Controller
{
    public function index()
    {
        return view('admin.users', ['users' => User::orderBy('name')->paginate(50)]);
    }

    public function destroy(User $user)
    {
        $user->delete();

        return back();
    }
}
