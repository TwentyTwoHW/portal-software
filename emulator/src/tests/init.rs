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

#[functional_test_wrapper::functional_test(
    entropy = "0000000000000000000000000000000000000000000000000000000000000000"
)]
async fn test_generate_mnemonic_12words(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Uninitialized,
            firmware_version: None,
        }))
        .await?;

    tester
        .nfc(NfcAction::GenerateMnemonic(
            model::NumWordsMnemonic::Words12,
            model::bitcoin::Network::Signet,
            None,
        ))
        .await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABRklEQVR4nO2YURKDIAxEyf0PvR2FBNCiBOi0TtcPqVWSZ4hsQMKXDwIQgADPBcAi9h8CgAxhRBupRfwt9r8DwPlGCOprO7VaBwDEGYFoXp2kdgLAPQTmsmwzQHeCzQLUQagiMJaE3Rho5cAWi5Ec0DTuZEeV/WUrg1/BzMdILSDAHwMskEQCSK2vzjog6s6SemCbAftnwUL1ZFE94JyGG/o/Vw+4xvOuIvLXA24VOuk/8nAM1APqv4+jGfIS4KP1QDPrYQ3rAQIQgAAEeAwACHC6FtPVXO7Z0nffSykrDtPCrKYwK0ku98t4CmbwCkBPypPJEp31EhwfSX6QHs49stFrgFAQVwBpTwChfIsjgFIE3SrIPfQGwnQEILcAkAoghaQrAnMA1ncOwMpKHJOw9hhsZfA2CW3VcjDKeYBaQAACEIAA1fECvNkjRpSzZRoAAAAASUVORK5CYII=", None).await?;

    const SCREENS: [&'static str; 6] = [
        "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABW0lEQVR4nO2YjQ6DIAyE6fs/9O0H2gJjSmXObDkzXVBov5TKFSVdfBCAAARYBcDQBObtLkcA/wKAGI13z760Xf5RzmAEIKGZV9fiF72ff9EpgByJewcgFiCJ5gDSxQCxKdgDCE/Bw7meH8mBcBJCs3iWIFn6y/AtmCTo++DbazPFiAC/DPBGB9P8K3gCAGJSeA5ATFiOqeFzxVTZbVfC4wBRNcwMVbir0GM+uq4FEq0HaskrHs1xPAJ37wsAJj7HpyBWE54AoEk4Ww9oDkjTHuVDDCBQD0iXA20VgnASsh4gAAEIQIDLAECAl7bKWr3xrbbOKJWg3RTtUmmyKiV8RL4kM7gFoBflcbJCZ6O8Mm3H5i5m4lnwmdFtgFQRNwBF46uvYgMApUhaIvgIfYC0HAHILgCkASghmYrAGoCNXQPwD0B9ErYefWcwTELbtXRGuQ5QCwhAAAIQoDluMq0nRo7q2NIAAAAASUVORK5CYII=",
        "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABc0lEQVR4nO2Yi44DIQhF4f8/+u5uBcRHOuDMpmnCJB3H+OCEohdl+vBTAAVQADkAPA9cAGxTR2h+AfDqpt2nEu2bl/YAAMc80KyoIZhVpeNtGQKIuHdrwBzoDEpDBuBvFMcBnMENmPiKcB1ovi0DwENQ7lzuHBGNAf3lY0DibiiTMdB9xoerYKZIrgJKrYYSowIogEu1jMsmP2bz+wFSyca8w3U11J0yDZDaAlfVY81DuKslZwBwmpthBOCwDB4lJJMuPgoQSkg2TmgFiNy/cuaBSD6wxoBFgq9wAiKXD6yrALTNig0pvQ+c5QPILb1/2IpxPFepYQEUQAF8HgAFsNTleMte6JxUgt0NhbsREjm087pTxle1vcgmfAegL0sz+1ejs1GMuYvYgXTuI/qk7wHIEQ8AovE9A9oBKAXplUEfoQ2g2x4AXwKABwBxScgD9wBs7D0AS+gwB+FokeyWaBuEdkqZJq19oLSgAAqgAApgeH4AZlRCRrAgGJAAAAAASUVORK5CYII=",
        "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABYklEQVR4nO2YYZOEIAiG4f//6PemWwTkSnHzptkd+lBjKTwCgsn08FUABVAAmwFwIhBDJbxX7QcDYE7TusSn+86HMnmPo/Xql7UAODNXeOkQEtHTGEK/0dw4r18ktQm5iUEnCg+gVEkLgOeORgbAga4AzA2QBeD+ZRJA9F9jmI9jDHhdFy64hggAGIRLiHJbBdB2WAWKlgvC7EqoWlAABTDK1dO1/L8WOEmSHwSAVZhQkfkmwJEB17Kg1YTHAELRecAF9E0WaAB5CB8DoF0uWHCE2/WqGbr9wXt5YMUCW3LI+0IeB6hqWAAFUAC7AFAAf9pSYNl+eolcqQS7Uwj9K5emq9Hu7/i3+bqRChwBtFvjMTKh01GM2EX0QDrbCBM6BiBH3AFInQf5WUSARkFtm2Aj2gfQbQuApwDgDkBMkrLAPQAdew/ADn9iEPYa7cToNAh1zxaEVh6oWlAABVAABdBdP/C1QUaekSK7AAAAAElFTkSuQmCC",
        "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABSklEQVR4nO2Y4Q7CIAyE2/d/6GoGbaUSxw11f26JGhylX6C0Byo3PwQgAAEuAthnQ1sflwCaNgiMe7A2xrPZ7Gt7HcC0fVb9hyMJb5NfDACYN++bAFomRgUEOIa5FUCQJfgNwOF/EcJ8rSvA+D+4BMheMClRL2VXXFkCcBlYjAhAgI0SSIAC0JIPlIImOkBber6gB3oShovhUP81GGA90DyjgmRSBSfFCViCbwG0QW8EUDQeNYUAoAdmDscYAADMYxHRAxMdUHbB1TxAPUAAAhCAAP8HMAK8tTXO3nkADuF31O1UHlGJs7S6RssTcrNQvwKxcwD/cp4k63RhpVa7dD/WO6dFDvoZQF6IB4B+JxD3CFMApxCXCGnhL0y2Z8D0FMB0AOhTsjQDewBhuwcQospqEI4eJU4A0yCMU0sZlHmAtYAABCAAAYbnAc8PNUZDaZO8AAAAAElFTkSuQmCC",
        "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABe0lEQVR4nO2YYRODIAiG5f//6HdbCii5hOrWPrDb1WkKT4pAUHn4lwAJkAA3AyAsMAE+47FNArkUFML2r8pQZWxd3Mcc4Ae0AKgjXOxNpwK0TigFAxVtH0p+D6bPu9era4V3KzC0yYzDYgliW2ABJkB/B7DaXAtwjNHbgL0LACb9hzbQdpEb5DgF9q6KwIZt+t1+wLERuNV5nJD1OEBGwwToz6Sd/9Nw3Hm+5wBuzAcQhtFwPHg/absBqr8kZ0oyf9uY/5/lA+6caDBBfvM+JwgDSBw8uQX70BwyLrWBsDl+BQhJYt0ntqEDmOYGbhuI5ANfToHNEWKnIJoPZCxIgARIgAS4GQAJsGsTtN4iCQ8nfVstpc86tE4i0RT2i1kKFZx9rgD4wjxK1uhkFsEOaXrQBusMFXoMUDriAaB9iHBJaw7AFIXTBJ3BD1AurwBoCQAaANqSuFbgGoDMvQYg31ywRjhqLFIhnBqhVC+N0PQDGQsSIAESIAGG3wu2uFRGQs7+cQAAAABJRU5ErkJggg==",
        "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAx0lEQVR4nO3V0Q6DMAhAUfn/j2bLqoUyWNqH2cTcvTgt0gOtKsfmHwAAAAAAAAAAAAAAAAAA+AZoBdN4Uef9WkZKHqvVwGTaZwC0jb//tl5fSbTfN6R1cUc8ymcwLawG2LErLL4lCoArbsDKWcsKoFduEF+vSWIHkg76QlY6EDvhBlyiApBPfCNAiqWU7MFdBIyJfi6BX/tzf7hkEwD3FLjdYbu6nxf3DbPH9ux4FU/vgT8Ksvn4GgIAAAAAAAAAAAAAAGA74AWxK4JB071edwAAAABJRU5ErkJggg==",
    ];

    for screen in SCREENS {
        tester.tsc(true).await?;
        tester.display_assertion(screen, Some(100)).await?;
    }

    Ok(())
}

#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_load_config(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Initialized {
                unlocked: true,
                network: model::bitcoin::Network::Signet,
            },
            firmware_version: None,
        }))
        .await?;

    Ok(())
}

#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized-locked.bin")]
async fn test_locked(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Initialized {
                unlocked: false,
                network: model::bitcoin::Network::Signet,
            },
            firmware_version: None,
        }))
        .await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAfklEQVR4nO3VsQ7AIAhFUfj/j34dgFg3TVMZvC5oongSFd2aGwAAAAAAAAAAAAAAAAAAWAeo5irXZVT0XZlQe3n3Aa8NPWKNfUzUcuIvgBGnPY8CbLJ0ASJLXY1GwJVHcP4SyhufoVXl6SlE/AUAAAAAAAAAAAAAAAAA8FN7APK2WUEuePxjAAAAAElFTkSuQmCC", None).await?;

    tester.nfc(NfcAction::DisplayAddress(42)).await?;
    tester.nfc_assertion(model::Reply::Locked).await?;

    tester.nfc(NfcAction::Unlock("paircode".into())).await?;
    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAx0lEQVR4nO3V0Q6DMAhAUfn/j2bLqoUyWNqH2cTcvTgt0gOtKsfmHwAAAAAAAAAAAAAAAAAA+AZoBdN4Uef9WkZKHqvVwGTaZwC0jb//tl5fSbTfN6R1cUc8ymcwLawG2LErLL4lCoArbsDKWcsKoFduEF+vSWIHkg76QlY6EDvhBlyiApBPfCNAiqWU7MFdBIyJfi6BX/tzf7hkEwD3FLjdYbu6nxf3DbPH9ux4FU/vgT8Ksvn4GgIAAAAAAAAAAAAAAGA74AWxK4JB071edwAAAABJRU5ErkJggg==", None).await?;

    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Initialized {
                unlocked: true,
                network: model::bitcoin::Network::Signet,
            },
            firmware_version: None,
        }))
        .await?;

    Ok(())
}
