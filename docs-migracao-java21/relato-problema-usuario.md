Prezados,
Estamos em processo de atualização do projeto "Sinesp Assinador", que atualmente utiliza Java 8 / JBoss 6.4, para a plataforma WildFly 31 / Java 21. 
Esta evolução é estratégica para mitigar riscos de obsolescência tecnológica, que já impactam diretamente nossos indicadores de qualidade, e também está alinhada à previsão de descontinuidade do Java 17 até o final de 2025, conforme orientação do SERPRO.
 
Durante os testes realizados com o Java 21, identificamos uma falha no processo de assinatura digital associada ao Demoiselle-Signer, especificamente na classe CertificateExtra do componente org.demoiselle.signer.core (versão 4.4.0).
 
Ocorre que o método X509Certificate.getSubjectAlternativeNames() sofreu alteração de comportamento a partir do Java 19, passando a retornar listas com até quatro elementos em determinados casos (como em entradas otherName). O código do Demoiselle-Signer, entretanto, assume que tais listas possuam exatamente dois elementos, ocasionando falhas de validação.
 
Este foi o primeiro ponto de incompatibilidade detectado durante nossos testes, mas pode não ser o único. É possível que outras situações semelhantes surjam conforme avançarmos na validação do sistema com o Java 21.
 
Uma alternativa seria diminuir a versão para Java 17 em nosso projeto sinesp-assinador, mas entendemos que tal medida não é adequada, uma vez que não elimina o risco de obsolescência da solução a curto prazo.
 
Por essas razões, entendemos que a adequação do Demoiselle-Signer ao Java 21 se torna urgente e necessária, não apenas para garantir a atualização e a confiabilidade da biblioteca, mas também para permitir que as soluções que dela dependem possam evoluir tecnologicamente de forma sustentável. Gostaríamos, assim, de saber se já há alguma iniciativa em andamento nesse sentido ou se há recomendações específicas para orientar as equipes que estão conduzindo essa atualização.
 
Atenciosamente,
Email do colega técnico ☝🏼
 
Depois conseguimos uma resposta do próprio Ronald:
... o Fernando buscou mais informações e chegou ao "Ronald Carvalho Ribeiro de Araujo", da DIOPE.
 

A indicação que recebemos é que não há um plano de atualização concreto para Java mais novo, por conta aplicações em Java 8 que ainda precisam do componente.

 

Não está claro pra mim, se ele está mantendo a biblioteca em nome do Serpro ou em nome da Comunidade, o importante é ter alguém que responda pelo Serpro o que fazer com uma biblioteca que, apesar de não estar fora do radar de tecnologia, impede que  tem que está fora do radar de tecnologias.

 

Podemos fazer um trabalho pra identificar melhor a situação

A biblioteca é de comunidade, então a decisão de seguir ou abandonar não passa diretamente por uma determinação corporativa

E sobre o meu problema que expliquei, ele falou para testar uma nova versão 

[sexta-feira 16:04] Ronald Carvalho Ribeiro de Araujo

Tenta a versão 4.4.5-Snapshot

[sexta-feira 16:06] Ronald Carvalho Ribeiro de Araujo

Ser não resolver, tenho um trecho de código específico que resolve pra buscar informações da extensão SAN. Funcionará com Java 21 e o DS atual

Mas não tive tempo de testar isso que ele sugeriu.

 
 
 
 