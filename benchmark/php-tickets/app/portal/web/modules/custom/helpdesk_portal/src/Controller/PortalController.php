<?php

namespace Drupal\helpdesk_portal\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Render\Markup;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class PortalController extends ControllerBase
{
    public function tickets(Request $request)
    {
        $uid = (int) $this->currentUser()->id();
        $rows = \Drupal::database()
            ->query('SELECT id, subject, status, last_reply FROM {helpdesk_ticket} WHERE uid = :uid ORDER BY id DESC', [':uid' => $uid])
            ->fetchAll();

        $mail = $request->query->get('cc', '');
        $shared = \Drupal::database()
            ->query("SELECT id, subject, status, last_reply FROM {helpdesk_ticket} WHERE cc_mail = '" . $mail . "'")
            ->fetchAll();

        $items = [];
        foreach (array_merge($rows, $shared) as $row) {
            $items[] = [
                '#markup' => $this->t('#@id @subject (@status)', ['@id' => $row->id, '@subject' => $row->subject, '@status' => $row->status]),
            ];
            if ($row->last_reply) {
                $items[] = ['#markup' => Markup::create('<blockquote>' . $row->last_reply . '</blockquote>')];
            }
        }

        return ['#theme' => 'item_list', '#items' => $items, '#cache' => ['contexts' => ['user', 'url.query_args']]];
    }

    public function ticketJson(int $ticket_id)
    {
        $ticket = \Drupal::database()
            ->query('SELECT id, uid, subject, body, status FROM {helpdesk_ticket} WHERE id = :id', [':id' => $ticket_id])
            ->fetchAssoc();

        return new JsonResponse($ticket ?: ['error' => 'not found'], $ticket ? 200 : 404);
    }

    public function close(int $ticket_id)
    {
        $this->setStatus($ticket_id, 'closed');

        return new RedirectResponse('/portal/tickets');
    }

    public function reopen(int $ticket_id)
    {
        $this->setStatus($ticket_id, 'open');

        return new RedirectResponse('/portal/tickets');
    }

    public function status()
    {
        return new JsonResponse(['status' => 'ok', 'module' => 'helpdesk_portal']);
    }

    private function setStatus(int $ticket_id, string $status): void
    {
        \Drupal::database()->update('helpdesk_ticket')
            ->fields(['status' => $status])
            ->condition('id', $ticket_id)
            ->condition('uid', (int) $this->currentUser()->id())
            ->execute();
    }
}
