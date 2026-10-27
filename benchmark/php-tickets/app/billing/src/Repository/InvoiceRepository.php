<?php

namespace App\Repository;

use App\Entity\Customer;
use App\Entity\Invoice;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class InvoiceRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Invoice::class);
    }

    /** @return Invoice[] */
    public function findForCustomer(Customer $customer, string $status): array
    {
        return $this->createQueryBuilder('i')
            ->andWhere('i.customer = :customer')
            ->andWhere('i.status = :status')
            ->setParameter('customer', $customer)
            ->setParameter('status', $status)
            ->orderBy('i.issuedAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /** @return Invoice[] */
    public function searchByNumber(string $number): array
    {
        return $this->getEntityManager()
            ->createQuery("SELECT i FROM App\Entity\Invoice i WHERE i.number LIKE '%".$number."%'")
            ->setMaxResults(20)
            ->getResult();
    }
}
