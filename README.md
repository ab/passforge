
# TODO

- add test vectors to site
- implementation for iOS?
- tune iterations used for each strengthening factor
- add about page
  - security
    - threat model
      - brute force on a leaked password
        If a site you use suffers a breach of their passwords, you are still
        probably OK. Even if
        1. The site was storing passwords in plain text (shame on them).
        2. The attacker links the account to you via email address or similar.
        3. The attacker guesses you are using passforge, though the generated
           passwords will be indistinguishable from randomly generated ones.
        4. The attacker tries to brute force your master password and nickname.

        Provided that you chose a master password with high entropy, it will
        not be feasible for an attacker to recover it. The purpose of the
        strengthening factor is to guard against this possibility. You can make
        attacks of this form practically impossible by choosing a higher
        strengthening factor. The resilience of passforge to attacks like this
        is its primary advantage over similar zero-storage solutions that use a
        small or fixed number of hash function iterations.

    - strengthening factors
      http://www.zdnet.com/blog/hardware/cheap-gpus-are-rendering-strong-passwords-useless/13125
      http://blog.zorinaq.com/?e=43
  - implementations
    - speed
  - tradeoffs vs. competititon
- fix up android app
- fix up logo
