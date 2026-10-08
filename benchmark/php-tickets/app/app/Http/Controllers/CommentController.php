<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    public function store(Request $request, Ticket $ticket)
    {
        $this->authorize('update', $ticket);

        $data = $request->validate(['body' => ['required', 'string', 'max:5000']]);

        $ticket->comments()->create([
            'body' => $data['body'],
            'user_id' => $request->user()->id,
        ]);

        return back();
    }
}
