<?php

namespace App\Controller;

use App\Entity\Invoice;
use App\Repository\InvoiceRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/invoices')]
#[IsGranted('ROLE_USER')]
class InvoiceController extends AbstractController
{
    #[Route('', name: 'invoice_index', methods: ['GET'])]
    public function index(Request $request, InvoiceRepository $invoices): Response
    {
        $status = $request->query->get('status', 'open');

        return $this->render('invoice/index.html.twig', [
            'invoices' => $invoices->findForCustomer($this->getUser(), $status),
        ]);
    }

    #[Route('/search', name: 'invoice_search', methods: ['GET'])]
    public function search(Request $request, InvoiceRepository $invoices): Response
    {
        $number = (string) $request->query->get('number', '');

        return $this->render('invoice/index.html.twig', [
            'invoices' => $invoices->searchByNumber($number),
        ]);
    }

    #[Route('/{id}', name: 'invoice_show', methods: ['GET'])]
    public function show(int $id, InvoiceRepository $invoices): Response
    {
        $invoice = $invoices->find($id) ?? throw $this->createNotFoundException();

        return $this->render('invoice/show.html.twig', ['invoice' => $invoice]);
    }

    #[Route('/{id}/pdf', name: 'invoice_pdf', methods: ['GET'])]
    public function pdf(Invoice $invoice): Response
    {
        $this->denyAccessUnlessGranted('VIEW', $invoice);

        return $this->file($invoice->getPdfPath());
    }
}
