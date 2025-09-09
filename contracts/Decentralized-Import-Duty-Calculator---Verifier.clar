(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-invalid-hs-code (err u101))
(define-constant err-invalid-country (err u102))
(define-constant err-payment-failed (err u103))
(define-constant err-invalid-proof (err u104))
(define-constant err-insufficient-signatures (err u105))
(define-constant err-already-signed (err u106))
(define-constant err-not-authorized-verifier (err u107))

(define-data-var min-fee uint u100)
(define-data-var max-fee uint u10000)
(define-data-var high-value-threshold uint u50000)
(define-data-var required-signatures uint u2)

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

(define-map authorized-verifiers
    { verifier: principal }
    { authorized: bool }
)

(define-map payment-signatures
    { payment-id: uint, verifier: principal }
    { signed: bool }
)

(define-map refund-requests
    { payment-id: uint }
    { requested: bool, refund-amount: uint, approved: bool }
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

(define-public (authorize-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set authorized-verifiers {verifier: verifier} {authorized: true}))
    )
)

(define-public (revoke-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set authorized-verifiers {verifier: verifier} {authorized: false}))
    )
)

(define-public (sign-payment (payment-id uint))
    (let (
        (payment (unwrap! (map-get? duty-payments {payment-id: payment-id}) err-invalid-proof))
        (verifier-auth (unwrap! (map-get? authorized-verifiers {verifier: tx-sender}) err-not-authorized-verifier))
        (already-signed (map-get? payment-signatures {payment-id: payment-id, verifier: tx-sender}))
    )
    (begin
        (asserts! (get authorized verifier-auth) err-not-authorized-verifier)
        (asserts! (is-none already-signed) err-already-signed)
        (asserts! (>= (get amount payment) (var-get high-value-threshold)) (ok true))
        (ok (map-set payment-signatures {payment-id: payment-id, verifier: tx-sender} {signed: true}))
    ))
)

(define-private (count-signatures (payment-id uint))
    (let (
        (authorized-list (list 
            (default-to false (get signed (map-get? payment-signatures {payment-id: payment-id, verifier: contract-owner})))
        ))
    )
    (len (filter is-signature-valid authorized-list)))
)

(define-private (is-signature-valid (signed bool))
    signed
)

(define-public (verify-multisig-payment (payment-id uint))
    (let (
        (payment (unwrap! (map-get? duty-payments {payment-id: payment-id}) err-invalid-proof))
        (signature-count (count-signatures payment-id))
    )
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (if (>= (get amount payment) (var-get high-value-threshold))
            (begin
                (asserts! (>= signature-count (var-get required-signatures)) err-insufficient-signatures)
                (ok (map-set duty-payments 
                    {payment-id: payment-id}
                    (merge payment {verified: true})
                ))
            )
            (ok (map-set duty-payments 
                {payment-id: payment-id}
                (merge payment {verified: true})
            ))
        )
    ))
)

(define-public (set-high-value-threshold (threshold uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (var-set high-value-threshold threshold))
    )
)

(define-public (set-required-signatures (count uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (var-set required-signatures count))
    )
)

(define-read-only (get-signature-count (payment-id uint))
    (ok (count-signatures payment-id))
)

(define-read-only (is-verifier-authorized (verifier principal))
    (ok (default-to false (get authorized (map-get? authorized-verifiers {verifier: verifier}))))
)
(define-public (request-refund (payment-id uint) (refund-amount uint))
    (let (
        (payment (unwrap! (map-get? duty-payments {payment-id: payment-id}) err-invalid-proof))
    )
    (begin
        (asserts! (is-eq tx-sender (get importer payment)) err-owner-only)
        (asserts! (<= refund-amount (get amount payment)) err-invalid-proof)
        (ok (map-set refund-requests {payment-id: payment-id} {requested: true, refund-amount: refund-amount, approved: false}))
    ))
)

(define-public (approve-refund (payment-id uint))
    (let (
        (request (unwrap! (map-get? refund-requests {payment-id: payment-id}) err-invalid-proof))
    )
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set refund-requests {payment-id: payment-id} (merge request {approved: true})))
    ))
)

(define-read-only (get-refund-status (payment-id uint))
    (ok (unwrap! (map-get? refund-requests {payment-id: payment-id}) err-invalid-proof))
)