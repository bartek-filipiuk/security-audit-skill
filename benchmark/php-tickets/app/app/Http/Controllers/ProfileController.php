<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function edit(Request $request)
    {
        return view('account.edit', ['user' => $request->user()]);
    }

    public function update(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'email' => ['required', 'email', 'unique:users,email,'.$request->user()->id],
        ]);

        $request->user()->update($request->all());

        return back()->with('status', 'Profile saved.');
    }

    public function avatar(Request $request)
    {
        $request->validate([
            'avatar' => ['required', 'image', 'mimes:jpg,png,webp', 'max:2048'],
        ]);

        $path = $request->file('avatar')->store('avatars', 'public');
        $request->user()->forceFill(['avatar_path' => $path])->save();

        return back();
    }
}
