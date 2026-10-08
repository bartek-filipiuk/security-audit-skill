<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: \App\Repository\InvoiceRepository::class)]
class Invoice
{
    #[ORM\Id, ORM\GeneratedValue, ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 32)]
    private string $number;

    #[ORM\Column(length: 16)]
    private string $status = 'open';

    #[ORM\ManyToOne(targetEntity: Customer::class)]
    private Customer $customer;

    #[ORM\Column(length: 255)]
    private string $pdfPath;

    public function getCustomer(): Customer
    {
        return $this->customer;
    }

    public function getPdfPath(): string
    {
        return $this->pdfPath;
    }
}
