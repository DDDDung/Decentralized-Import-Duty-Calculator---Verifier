(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-invalid-hs-code (err u101))
(define-constant err-invalid-country (err u102))
(define-constant err-payment-failed (err u103))
(define-constant err-invalid-proof (err u104))

(define-data-var min-fee uint u100)
(define-data-var max-fee uint u10000)

(define-map hs-codes 
    { code: (string-ascii 10) }
    { description: (string-ascii 100), base-rate: uint }
)

(define-map country-rates
    { country: (string-ascii 2), hs-code: (string-ascii 10) }
    { rate: uint }
)

(define-map duty-payments
    { payment-id: uint }
    {
        importer: principal,
        hs-code: (string-ascii 10),
        origin: (string-ascii 2),
        destination: (string-ascii 2),
        amount: uint,
        verified: bool
    }
)

(define-data-var payment-nonce uint u0)

(define-read-only (get-duty-rate (hs-code (string-ascii 10)) (origin (string-ascii 2)) (destination (string-ascii 2)))
    (let (
        (base-info (unwrap! (map-get? hs-codes {code: hs-code}) err-invalid-hs-code))
        (country-info (unwrap! (map-get? country-rates {country: origin, hs-code: hs-code}) err-invalid-country))
    )
    (ok {
        base-rate: (get base-rate base-info),
        country-rate: (get rate country-info)
    }))
)

(define-read-only (calculate-duty (hs-code (string-ascii 10)) (origin (string-ascii 2)) (destination (string-ascii 2)) (value uint))
    (let (
        (rates (unwrap! (get-duty-rate hs-code origin destination) err-invalid-hs-code))
        (base-rate (get base-rate rates))
        (country-rate (get country-rate rates))
        (total-rate (+ base-rate country-rate))
    )
    (ok (/ (* value total-rate) u10000)))
)

(define-public (register-hs-code (code (string-ascii 10)) (description (string-ascii 100)) (base-rate uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set hs-codes {code: code} {description: description, base-rate: base-rate}))
    )
)

(define-public (register-country-rate (country (string-ascii 2)) (hs-code (string-ascii 10)) (rate uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set country-rates {country: country, hs-code: hs-code} {rate: rate}))
    )
)

(define-public (submit-duty-payment (hs-code (string-ascii 10)) (origin (string-ascii 2)) (destination (string-ascii 2)) (value uint))
    (let (
        (duty-amount (unwrap! (calculate-duty hs-code origin destination value) err-invalid-hs-code))
        (payment-id (+ (var-get payment-nonce) u1))
    )
    (begin
        (var-set payment-nonce payment-id)
        (map-set duty-payments 
            {payment-id: payment-id}
            {
                importer: tx-sender,
                hs-code: hs-code,
                origin: origin,
                destination: destination,
                amount: duty-amount,
                verified: false
            }
        )
        (ok payment-id)
    ))
)

(define-public (verify-payment (payment-id uint))
    (let (
        (payment (unwrap! (map-get? duty-payments {payment-id: payment-id}) err-invalid-proof))
    )
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set duty-payments 
            {payment-id: payment-id}
            (merge payment {verified: true})
        ))
    ))
)

(define-read-only (get-payment-details (payment-id uint))
    (ok (unwrap! (map-get? duty-payments {payment-id: payment-id}) err-invalid-proof))
)