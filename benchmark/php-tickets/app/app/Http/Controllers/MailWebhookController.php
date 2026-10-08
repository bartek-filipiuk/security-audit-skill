<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Http\Request;

class MailWebhookController extends Controller
{
    public function __invoke(Request $request)
    {
        $expected = hash_hmac('sha256', $request->getContent(), config('services.mail.webhook_secret'));

        if (! hash_equals($expected, (string) $request->header('X-Mail-Signature'))) {
            abort(401);
        }

        $ticket = Ticket::where('reply_token', $request->input('token'))->firstOrFail();
        $ticket->comments()->create([
            'body' => strip_tags((string) $request->input('text')),
            'user_id' => $ticket->user_id,
        ]);

        return response()->noContent();
    }
}
