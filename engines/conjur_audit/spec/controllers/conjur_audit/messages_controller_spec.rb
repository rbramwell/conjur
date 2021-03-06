require 'rails_helper'

module ConjurAudit
  RSpec.describe MessagesController, type: :controller do
    describe "GET #index" do
      let(:messages) { JSON.parse response.body }

      it "returns audit messages" do
        add_message "foo"
        get :index
        expect(response).to have_http_status(:success)
        expect(messages).to match [include('message' => 'foo')]
      end
      
      it "allows filtering" do
        add_message "foo", severity: 4
        add_message "bar", severity: 5
        
        get :index, severity: 4

        expect(response).to have_http_status(:success)
        expect(messages).to match [include('message' => 'foo')]
      end

      it "returns 404 if no matching entries are found" do
        add_message "bar", severity: 5
        get :index, severity: 4
        expect(response).to have_http_status(:not_found)
      end

      context "with structured data in messages" do
        before do
          add_message "foo", sdata: { foo: { present: true } }
          add_message "bar", sdata: { bar: { present: true } }
        end

        it "allows filtering on sdata" do
          get :index, 'foo/present' => true
          expect(response).to have_http_status(:success)
          expect(messages).to match [include('message' => 'foo')]
        end

        it "allows conjur-specific filtering on resources" do
          add_message "resource test", sdata: { "subject@43868": { resource: "acct:kind:id" } }

          get :index, resource: "acct:kind:id"

          expect(response).to have_http_status(:success)
          expect(messages).to match [include("message" => "resource test")]
        end

        it "allows conjur-specific filtering on roles" do
          add_message "resource test", sdata: { "subject@43868": { resource: "acct:kind:id" } }
          add_message "role test", sdata: { "subject@43868": { role: "acct:kind:id" } }

          get :index, role: "acct:kind:id"

          expect(response).to have_http_status(:success)
          expect(messages).to match [include("message" => "role test")]
        end

        it "allows conjur-specific filtering on entities" do
          add_message "resource test", sdata: { "subject@43868": { resource: "acct:kind:id" } }
          add_message "role test", sdata: { "subject@43868": { role: "acct:kind:id" } }

          get :index, entity: "acct:kind:id"

          expect(response).to have_http_status(:success)
          expect(messages).to match_array [
            include("message" => "role test"),
            include("message" => "resource test")
          ]
        end

        it "supports combined queries" do
          add_message "resource test 4v", severity: 4, sdata: { "subject@43868": { resource: "acct:kind:id" }, other: { param: "value" } }
          add_message "resource test 4", severity: 4, sdata: { "subject@43868": { resource: "acct:kind:id" } }
          add_message "resource test 5", severity: 5, sdata: { "subject@43868": { resource: "acct:kind:id" } }
          add_message "resource test 5v", severity: 5, sdata: { "subject@43868": { resource: "acct:kind:id" }, other: { param: "value" } }

          get :index, resource: "acct:kind:id", severity: 4, 'other/param': 'value'

          expect(response).to have_http_status(:success)
          expect(messages).to match [include("message" => "resource test 4v")]
        end
      end
    end
  end
end
