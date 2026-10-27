# Helpdesk

Support tickets for customers of the studio, with a billing service and a
customer portal on the public website.

## Layout

- `/` (Laravel 11): the helpdesk itself. Customers open tickets, add comments
  and attachments; staff answer and run reports. Web routes in
  `routes/web.php`, the JSON API for the mobile app in `routes/api.php`
  (Sanctum tokens).
- `billing/` (Symfony 7): invoices for paid support plans, Doctrine ORM.
- `portal/` (Drupal 10): the public website; the custom module
  `helpdesk_portal` shows a customer's tickets inside the portal.

## Running locally

    composer install
    cp .env.example .env && php artisan key:generate
    php artisan migrate
    php artisan serve

    cd billing && composer install && symfony serve
    cd portal && composer install && drush site:install

## Security

- Every ticket route requires a signed-in user; customers only see their own
  tickets, staff see all of them.
- The API uses Sanctum tokens.
- Staff-only screens are behind the `admin` gate.
- Mail provider webhooks are signed (HMAC-SHA256).
- Invoices are visible to their customer only.
