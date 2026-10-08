<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Http\Request;

class AttachmentController extends Controller
{
    public function store(Request $request, Ticket $ticket)
    {
        $this->authorize('update', $ticket);

        $request->validate(['file' => ['required', 'file', 'max:10240']]);
        $file = $request->file('file');

        $path = $file->storeAs('attachments/'.$ticket->id, $file->getClientOriginalName(), 'public');

        $ticket->attachments()->create([
            'path' => $path,
            'name' => $file->getClientOriginalName(),
            'size' => $file->getSize(),
        ]);

        return back();
    }
}
