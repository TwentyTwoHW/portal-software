// Portal Hardware Wallet firmware and supporting software libraries
//
// Copyright (C) 2024 Alekos Filini
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use super::*;

#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_display_address(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAx0lEQVR4nO3V0Q6DMAhAUfn/j2bLqoUyWNqH2cTcvTgt0gOtKsfmHwAAAAAAAAAAAAAAAAAA+AZoBdN4Uef9WkZKHqvVwGTaZwC0jb//tl5fSbTfN6R1cUc8ymcwLawG2LErLL4lCoArbsDKWcsKoFduEF+vSWIHkg76QlY6EDvhBlyiApBPfCNAiqWU7MFdBIyJfi6BX/tzf7hkEwD3FLjdYbu6nxf3DbPH9ux4FU/vgT8Ksvn4GgIAAAAAAAAAAAAAAGA74AWxK4JB071edwAAAABJRU5ErkJggg==", None).await?;

    tester.nfc(NfcAction::DisplayAddress(42)).await?;
    tester.wait_ticks(4).await?;

    tester.tsc(true).await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABoElEQVR4nO2Xi5LDIAhF4f8/+m6nu/ISom2TzXSGzDRNo8XjBUGZbr4aoAEaoAEaoAG+AACmH8r+eHcuOwAsI9cAR01nAKzt/wvA0Hl45fES0TuQpj2q1xQId+hQ7uvZdDlA9ZKuB7AuyJuuBsimOXnnXADn6IMY0FjF83MOwOgnT/MqcE0sGKco8MnavxHAOu4eBbBpvcsx16KGhPeZn0C2jnAFAPvmAwDoCgSNcNS4tAY5wmrjKQAIOfsQICQz+/CbcpyYU1qKucvVxXJGOYDkUfMgv9goVWR9CD4nw6KKgdlmkG7uUzjor93pXfwhUW4BQFIIli6AGaQCfk+B1VKdFSoDeT8G2Cf5rRjIqsKOAvMqcKszKI/jlApxF2VadC1ogPsB0AAj+UL22bq49USKURDJ1PfQxWR/PaJCJjntCBAAxo1IB2MxwQS2xSLrklhRANfKMiGWLVIOYI8atABQEGOFYfuVABsKgJcAugswuxbjOLIAL7tgDeAMeLItBXSbE4PQj0hyKk2DEG62EcCVU3Qe6FrQAA3QAA3wuH4AkLygRpKIQXAAAAAASUVORK5CYII=", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAx0lEQVR4nO3V0Q6DMAhAUfn/j2bLqoUyWNqH2cTcvTgt0gOtKsfmHwAAAAAAAAAAAAAAAAAA+AZoBdN4Uef9WkZKHqvVwGTaZwC0jb//tl5fSbTfN6R1cUc8ymcwLawG2LErLL4lCoArbsDKWcsKoFduEF+vSWIHkg76QlY6EDvhBlyiApBPfCNAiqWU7MFdBIyJfi6BX/tzf7hkEwD3FLjdYbu6nxf3DbPH9ux4FU/vgT8Ksvn4GgIAAAAAAAAAAAAAAGA74AWxK4JB071edwAAAABJRU5ErkJggg==", None).await?;

    tester
        .nfc_assertion(model::Reply::Address(
            "tb1qulky7g0u2pgqvqs4azezaz979cpg00w7zwg49e".to_string(),
        ))
        .await?;

    Ok(())
}

#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_public_descriptors(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAx0lEQVR4nO3V0Q6DMAhAUfn/j2bLqoUyWNqH2cTcvTgt0gOtKsfmHwAAAAAAAAAAAAAAAAAA+AZoBdN4Uef9WkZKHqvVwGTaZwC0jb//tl5fSbTfN6R1cUc8ymcwLawG2LErLL4lCoArbsDKWcsKoFduEF+vSWIHkg76QlY6EDvhBlyiApBPfCNAiqWU7MFdBIyJfi6BX/tzf7hkEwD3FLjdYbu6nxf3DbPH9ux4FU/vgT8Ksvn4GgIAAAAAAAAAAAAAAGA74AWxK4JB071edwAAAABJRU5ErkJggg==", None).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABf0lEQVR4nO2Yiw6DMAhF4f8/mi22loe0K/MVI8vmTK30CHivG8LNrwRIgARIgARIgMcA0Fm88wCRtQOzHwdQvr/b5V0GqcQpI989ikSO9UBZpn7qThsxQ6eVgK+3pQIExQU9wCveA3B3BoY9IAEmIaJCNLgLdJlmQ/8tbXSQKiZA2jH2JPeESpAXGr2Agaibqf1z/dAuwJ4OOxCA9QXkHrLvVgNcnRhVBa1Jd/j6APJj9JZluG3NgGvSbn66AGYHwPcaY43tmGdRbn0GAOsEat97Abz++JEBOX5ABqZ0AM3G7YENwKZZHJOezIBqY93ZBPJhRMwW3qxuHoQwwOXOlABpx01wXg+AVXLYvPgfgWp0yALNptQkYjlqfiAqFZE6xedqgHWz8jBZpUNxmppiAiDxaSq8nGcA+CoMQNU0Es8GFoCvewxQ5pEqfCQDhNDPgJB+XszJgIx9KICf5EAJuAmXYpgm1CvWPIJfPi4G2K4dNOGLdSC9IAESIAFeD/AB8uZrRnAl7rcAAAAASUVORK5CYII=", None).await?;

    tester.tsc(true).await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAx0lEQVR4nO3V0Q6DMAhAUfn/j2bLqoUyWNqH2cTcvTgt0gOtKsfmHwAAAAAAAAAAAAAAAAAA+AZoBdN4Uef9WkZKHqvVwGTaZwC0jb//tl5fSbTfN6R1cUc8ymcwLawG2LErLL4lCoArbsDKWcsKoFduEF+vSWIHkg76QlY6EDvhBlyiApBPfCNAiqWU7MFdBIyJfi6BX/tzf7hkEwD3FLjdYbu6nxf3DbPH9ux4FU/vgT8Ksvn4GgIAAAAAAAAAAAAAAGA74AWxK4JB071edwAAAABJRU5ErkJggg==", None).await?;

    tester
        .nfc_assertion(model::Reply::Descriptor{
            external: "wpkh([2bd3bdd7/84'/1'/0']tpubDCPMyXQR36y1uRVgsLGeNgN3awiqucyHGUa7pjQygcRbrbbWCMeRKnShL2hRfvE4zcQ9m9fjMMZHjSoQVatYyuwKqp6AyszbRt6s4iSXChJ/0/*)#klvmrneg".to_string(),
            internal: Some("wpkh([2bd3bdd7/84'/1'/0']tpubDCPMyXQR36y1uRVgsLGeNgN3awiqucyHGUa7pjQygcRbrbbWCMeRKnShL2hRfvE4zcQ9m9fjMMZHjSoQVatYyuwKqp6AyszbRt6s4iSXChJ/1/*)#8tf67xfs".to_string()),
        })
        .await?;

    Ok(())
}
